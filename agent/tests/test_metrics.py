# -*- coding: utf-8 -*-
"""Local reliability metrics: deterministic windows, semantics and read-only safety."""
import datetime
import json
import os
import tempfile
import unittest

import _ctx  # noqa: F401
import learning
import metrics
import pool as pool_mod
from providers.base import Provider, ProviderError, ProviderErrorKind


NOW = datetime.datetime(2026, 8, 22, 12, 0, 0)


class TestLocalMetrics(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.pool = pool_mod.Pool(os.path.join(self.tmp.name, "state.db"), server="node")

    def tearDown(self):
        self.pool.close()
        self.tmp.cleanup()

    def event(self, ts, action, result, actor="auto", detail="", payload=None):
        raw = json.dumps(payload, allow_nan=False) if payload is not None else None
        self.pool.conn.execute(
            "INSERT INTO event(ts,server,actor,action,result,detail,payload_json) "
            "VALUES(?,?,?,?,?,?,?)", (ts, "node", actor, action, result, detail, raw))

    def probe(self, ts, ok, tg, current=1):
        self.pool.conn.execute(
            "INSERT INTO probe_log(ts,uid,provider,ok,tg_ok,is_current,strategy) "
            "VALUES(?,?,?,?,?,?,?)", (ts, "p:a", "p", ok, tg, current, "speed"))

    def test_empty_report_is_strict_json_and_read_only(self):
        before = self.pool.conn.total_changes
        report = metrics.local_report(self.pool, now=NOW)
        after = self.pool.conn.total_changes
        self.assertEqual(before, after)
        self.assertIsNone(report["availability"]["egress"]["ratio"])
        self.assertIsNone(report["fault_recovery"]["p95_seconds"])
        self.assertIsNone(report["switches"]["success_rate"])
        json.dumps(report, allow_nan=False)

    def test_all_required_metric_families_and_window_boundaries(self):
        self.probe("2026-08-22 09:00:00", 1, 1)
        self.probe("2026-08-22 09:05:00", 0, 0)
        self.probe("2026-08-22 09:10:00", 0, 0, current=0)  # reserve is not availability

        self.event("2026-08-22 10:00:00", "proxy-fault", "confirmed")
        self.event("2026-08-22 10:02:00", "rotate", "ok", payload={
            "freshness": {"p:a": 0.5}})
        self.event("2026-08-22 10:03:00", "strategy-apply", "fail")
        self.event("2026-08-22 10:10:00", "rollback", "ok", actor="user",
                   detail=json.dumps({"bad_ip": "10.0.0.2", "good_ip": "10.0.0.1"}))
        self.event("2026-08-22 10:11:00", "strategy-apply", "stale", payload={
            "freshness": {"p:b": 1.0}})
        self.event("2026-08-22 10:12:00", "provider-api", "rate-limit")
        self.event("2026-08-22 10:13:00", "provider-api", "network")
        self.event("2026-08-22 10:14:00", "buy", "denied")

        # State was MANUAL at the window boundary; only the in-window slice counts.
        self.event("2026-07-20 12:00:00", "selection-mode", "manual", actor="user")
        self.event("2026-07-24 12:00:00", "selection-mode", "auto",
                   detail="подтверждённый proxy fault")
        self.event("2026-08-01 00:00:00", "selection-mode", "manual", actor="user")
        self.event("2026-08-01 01:00:00", "selection-mode", "auto",
                   detail="выбор стратегии speed")

        for ts, price, currency, op in (
                ("2026-08-22 08:00:00", 4, "RUB", "buy"),
                ("2026-08-22 08:10:00", 2, "USD", "prolong"),
                ("2026-08-22 08:20:00", 999, "RUB", "delete"),
                ("2026-08-22 08:30:00", "bad", "RUB", "buy"),
                ("2026-08-22 08:40:00", -100, "RUB", "buy")):
            self.pool.conn.execute(
                "INSERT INTO money(ts,provider,op,price,currency) VALUES(?,?,?,?,?)",
                (ts, "p", op, price, currency))
        for day, ok, fail in (("2026-08-16", 8, 2), ("2026-08-22", 9, 1)):
            self.pool.conn.execute(
                "INSERT INTO learning_bucket(day,level,probes_ok,probes_fail) "
                "VALUES(?,?,?,?)", (day, "global", ok, fail))
        for day in ("2026-08-20", "2026-08-21"):
            self.pool.conn.execute(
                "INSERT INTO shadow_decision(ts,server,formula_version,mode,strategy,"
                "candidate_count,scores_json) VALUES(?,?,?,?,?,?,?)",
                (day + " 12:00:00", "node", learning.FORMULA_VERSION,
                 "shadow", "speed", 1, "[]"))

        # Bad/future rows are counted as data-quality issues, never included.
        self.event("not-a-date", "rotate", "ok")
        self.probe("2026-08-23 00:00:00", 1, 1)
        self.pool.conn.commit()

        report = metrics.local_report(self.pool, now=NOW, window_days=30)
        self.assertEqual(report["availability"]["egress"],
                         {"samples": 2, "successful": 1, "ratio": 0.5})
        self.assertEqual(report["availability"]["telegram"]["ratio"], 0.5)
        self.assertEqual(report["fault_recovery"]["p95_seconds"], 120.0)
        self.assertTrue(report["fault_recovery"]["meets_target"])
        self.assertEqual((report["switches"]["attempts"],
                          report["switches"]["successful"]), (2, 1))
        self.assertEqual(report["switches"]["false_switches"], 1)
        self.assertEqual(report["manual"]["seconds"], 90000.0)
        self.assertEqual((report["manual"]["entries"], report["manual"]["exits"]),
                         (1, 2))
        self.assertEqual(report["stale_score"]["with_stale_inputs"], 1)
        self.assertEqual(report["stale_score"]["superseded_decisions"], 1)
        self.assertEqual((report["provider_api"]["errors"],
                          report["provider_api"]["rate_limits"]), (2, 1))
        self.assertEqual(report["spend"]["by_currency"], [
            {"currency": "RUB", "amount": 4.0},
            {"currency": "USD", "amount": 2.0},
        ])
        self.assertEqual(report["spend"]["denied"], 1)
        self.assertEqual(report["spend"]["ignored_invalid_amounts"], 2)
        self.assertEqual(report["learning"]["coverage_days"], 2)
        self.assertEqual(report["learning"]["shadow_days"], 2)
        self.assertEqual(report["quality"]["malformed_timestamps"]["event"], 1)
        self.assertEqual(report["quality"]["future_rows_ignored"]["probe_log"], 1)
        json.dumps(report, allow_nan=False)

    def test_bounds_rows_and_clamps_window(self):
        for minute in range(3):
            self.event("2026-08-22 10:0%d:00" % minute, "rotate", "ok")
        self.pool.conn.commit()
        report = metrics.local_report(self.pool, now=NOW, window_days=999, max_rows=1)
        self.assertEqual(report["window_days"], metrics.MAX_WINDOW_DAYS)
        self.assertTrue(report["quality"]["truncated"]["event"])
        self.assertEqual(report["switches"]["successful"], 1)

    def test_same_ip_rollback_is_not_false_switch_or_switch_rollback(self):
        self.event("2026-08-22 10:00:00", "rotate", "ok")
        self.event("2026-08-22 10:02:00", "retune", "ok")
        self.event("2026-08-22 10:03:00", "rollback", "ok",
                   detail=json.dumps({"bad_ip": "10.0.0.2", "good_ip": "10.0.0.2"}))
        self.pool.conn.commit()
        switches = metrics.local_report(self.pool, now=NOW)["switches"]
        self.assertEqual((switches["rollbacks"], switches["false_switches"]), (0, 0))
        self.assertEqual(switches["rollback_rate"], 0.0)

    def test_deep_corrupt_payload_is_quarantined(self):
        nested = '{"freshness":' + ('[' * 5000) + '0' + (']' * 5000) + '}'
        self.pool.conn.execute(
            "INSERT INTO event(ts,actor,action,result,payload_json) VALUES(?,?,?,?,?)",
            ("2026-08-22 10:00:00", "auto", "strategy-apply", "held", nested))
        self.pool.conn.commit()
        report = metrics.local_report(self.pool, now=NOW)
        self.assertEqual(report["stale_score"]["corrupt_payloads"], 1)
        json.dumps(report, allow_nan=False)

    def test_learning_gate_uses_formula_mode_and_configured_minimum(self):
        # Irrelevant old/active formula rows must not qualify v2 shadow history.
        for offset in range(30):
            day = (NOW.date() - datetime.timedelta(days=offset)).isoformat()
            self.pool.conn.execute(
                "INSERT INTO shadow_decision(ts,server,formula_version,mode,strategy,"
                "candidate_count,scores_json) VALUES(?,?,?,?,?,?,?)",
                (day + " 01:00:00", "node", "old", "active", "speed", 1, "[]"))
        self.pool.conn.commit()
        cfg = {"server": "node", "learning": {"mode": "active",
               "shadow_min_days": 45, "owner_approved": True,
               "canary_servers": ["node"]}}
        status = metrics.local_report(self.pool, cfg=cfg, now=NOW)["learning"]
        self.assertEqual((status["shadow_days"], status["shadow_min_days"],
                          status["shadow_qualified"]), (0, 45, False))
        self.assertIn("shadow-days-0/45", status["activation_blockers"])

        for offset in range(45):
            day = (NOW.date() - datetime.timedelta(days=offset + 1)).isoformat()
            self.pool.conn.execute(
                "INSERT INTO shadow_decision(ts,server,formula_version,mode,strategy,"
                "candidate_count,scores_json) VALUES(?,?,?,?,?,?,?)",
                (day + " 01:00:00", "node", learning.FORMULA_VERSION,
                 "shadow", "speed", 1, "[]"))
        # Canary evidence after qualification is required for active mode.
        self.pool.conn.execute(
            "INSERT INTO shadow_decision(ts,server,formula_version,mode,strategy,"
            "candidate_count,scores_json) VALUES(?,?,?,?,?,?,?)",
            ("2026-08-22 02:00:00", "node", learning.FORMULA_VERSION,
             "canary", "speed", 1, "[]"))
        self.pool.conn.commit()
        report_status = metrics.local_report(self.pool, cfg=cfg, now=NOW)["learning"]
        actual = learning.activation_status(self.pool, cfg, server="node", now=NOW)
        self.assertEqual(report_status["shadow_days"], actual["coverage"]["days"])
        self.assertEqual(report_status["shadow_min_days"], actual["minimum_days"])
        self.assertEqual(report_status["activation_eligible"], actual["eligible"])


class _FailingProvider(Provider):
    name = "fixture"

    def fail(self):
        def request():
            raise ProviderError("sensitive upstream message", kind=ProviderErrorKind.RATE_LIMIT,
                                retry_after=17)
        return self._guarded("list", request)


class TestProviderMetricObserver(unittest.TestCase):
    def test_typed_error_is_persisted_without_message_or_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            pool = pool_mod.Pool(os.path.join(tmp, "state.db"), server="node")
            provider = _FailingProvider("top-secret-api-key")
            pool.observe_provider_errors({"fixture": provider}, actor="auto")
            with self.assertRaises(ProviderError):
                provider.fail()
            event = pool.events(1)[0]
            report = metrics.local_report(pool, now=datetime.datetime.now())
            pool.close()
        self.assertEqual((event["action"], event["result"]),
                         ("provider-api", "rate-limit"))
        self.assertNotIn("top-secret-api-key", event["detail"])
        self.assertNotIn("sensitive upstream message", event["detail"])
        self.assertEqual(report["provider_api"]["rate_limits"], 1)


if __name__ == "__main__":
    unittest.main()
