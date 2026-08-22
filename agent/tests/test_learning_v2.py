# -*- coding: utf-8 -*-
import datetime
import os
import tempfile
import threading
import unittest
from unittest import mock

import _ctx  # noqa: F401
import learning
import pool as pool_mod
import probe


TODAY = datetime.date(2026, 8, 22)


def bucket(age, ok=0, fail=0, tg_ok=0, tg_fail=0, geo_ok=0, geo_fail=0,
           latency_sum=0, latency_count=0, drops=0, seconds=0):
    return {"day": (TODAY - datetime.timedelta(days=age)).isoformat(),
            "probes_ok": ok, "probes_fail": fail, "tg_ok": tg_ok,
            "tg_fail": tg_fail, "geo_ok": geo_ok, "geo_fail": geo_fail,
            "latency_sum": latency_sum, "latency_count": latency_count,
            "battle_drops": drops, "battle_seconds": seconds}


class TestLearningMath(unittest.TestCase):
    def test_decay_and_windows_do_not_keep_counters_forever(self):
        rows = [bucket(0, ok=10), bucket(10, fail=10), bucket(40, fail=100)]
        summary = learning.summarize_buckets(rows, now=TODAY, half_life_days=10)
        self.assertEqual(summary["windows"]["7"]["availability"]["sample_size"], 10.0)
        self.assertEqual(summary["windows"]["30"]["availability"]["sample_size"], 20.0)
        self.assertEqual(summary["windows"]["90"]["availability"]["sample_size"], 120.0)
        self.assertLess(summary["ewma"]["availability"]["fail"], 20.0,
                        "110 eternal failures must decay to a small recent weight")

    def test_features_remain_separate(self):
        summary = learning.summarize_buckets([
            bucket(0, ok=9, fail=1, tg_ok=2, tg_fail=8, geo_ok=10,
                   latency_sum=2000, latency_count=10, drops=2, seconds=7200)
        ], now=TODAY)
        ewma = summary["ewma"]
        self.assertEqual(ewma["availability"]["mean"], 0.9)
        self.assertEqual(ewma["telegram"]["mean"], 0.2)
        self.assertEqual(ewma["geo_honesty"]["mean"], 1.0)
        self.assertEqual(ewma["latency_ms"], 200.0)
        self.assertEqual(ewma["battle_drop_rate"], 1.0)

    def test_uncertainty_penalizes_small_sample(self):
        small = learning.wilson_interval(1, 1)
        large = learning.wilson_interval(100, 100)
        self.assertLess(small[0], large[0])
        self.assertGreater(small[1] - small[0], large[1] - large[0])

    def test_cold_child_inherits_parent_mature_child_overrides(self):
        parent = {"level": "provider", "ewma": {
            "availability": {"success": 90, "fail": 10}}}
        cold = {"level": "country", "ewma": {
            "availability": {"success": 1, "fail": 0}}}
        mature = {"level": "country", "ewma": {
            "availability": {"success": 10, "fail": 90}}}
        inherited = learning.hierarchical_estimate([parent, cold], prior_strength=20)
        overridden = learning.hierarchical_estimate([parent, mature], prior_strength=20)
        self.assertGreater(inherited["mean"], 0.75)
        self.assertLess(inherited["maturity"], 0.1)
        self.assertLess(overridden["mean"], 0.3)
        self.assertGreater(overridden["maturity"], 0.8)


class TestLearningBuckets(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.pool = pool_mod.Pool(os.path.join(self.tmp.name, "state.db"), server="test")
        self.uid = self.pool.upsert_proxy({
            "provider": "proxy6", "ext_id": "1", "ip": "1.1.1.1", "host": "1.1.1.1",
            "port_http": 8080, "port_socks5": 1080, "user": "u", "password": "p",
            "country": "fi", "ip_version": 4, "kind": "dedicated",
            "date_end": None, "descr": ""})

    def tearDown(self):
        self.pool.close()
        self.tmp.cleanup()

    def row(self):
        return dict(self.pool.get(self.uid))

    def test_probe_writes_all_hierarchy_levels_and_legacy_aggregate(self):
        self.pool.record_probe(self.uid, {
            "ok": True, "tg_ok": False, "geo_agree": True,
            "latency_ms": 125, "socks_ok": True})
        levels = {item["level"] for item in self.pool.learning_buckets()}
        self.assertEqual(levels, {"global", "provider", "provider_family",
                                  "provider_country", "uid"})
        country = self.pool.learning_buckets(
            level="provider_country", provider="proxy6", country="fi")[0]
        self.assertEqual((country["probes_ok"], country["tg_fail"],
                          country["geo_ok"], country["latency_sum"]),
                         (1, 1, 1, 125.0))
        legacy = self.pool.stability_get("proxy6", "fi")
        self.assertEqual(legacy["probes_ok"], 1)

    def test_daily_upsert_and_battle_features(self):
        day = "2026-08-22"
        self.pool.learning_bump_probe(self.row(), {"ok": False, "tg_ok": False}, day=day)
        self.pool.learning_bump_probe(self.row(), {"ok": True, "tg_ok": True}, day=day)
        self.pool.learning_bump_drop(self.row(), day=day)
        self.pool.learning_bump_battle(self.row(), 600, day=day)
        global_row = self.pool.learning_buckets(level="global", since_day=day)[0]
        self.assertEqual((global_row["probes_ok"], global_row["probes_fail"],
                          global_row["battle_drops"], global_row["battle_seconds"]),
                         (1, 1, 1, 600))

    def test_legacy_stability_table_is_retained_for_audit(self):
        names = {row[0] for row in self.pool.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertIn("stability", names)
        self.assertIn("learning_bucket", names)

    def test_probe_dual_write_rolls_back_and_retry_is_not_duplicated(self):
        before = self.row()
        self.pool.conn.execute(
            "CREATE TRIGGER fail_learning BEFORE INSERT ON learning_bucket "
            "BEGIN SELECT RAISE(ABORT, 'injected learning failure'); END")
        self.pool.conn.commit()
        result = {"ok": True, "tg_ok": True, "geo_agree": True,
                  "latency_ms": 50, "socks_ok": True, "asn": "AS64500"}
        with self.assertRaises(pool_mod.PoolDBError):
            self.pool.record_probe(self.uid, result)
        after = self.row()
        self.assertEqual(after["last_probe_at"], before["last_probe_at"])
        self.assertEqual(after["probe_ok"], before["probe_ok"])
        self.assertEqual(self.pool.conn.execute(
            "SELECT COUNT(*) FROM probe_log").fetchone()[0], 0)
        self.assertIsNone(self.pool.stability_get("proxy6", "fi"))
        self.assertEqual(self.pool.learning_buckets(), [])

        self.pool.conn.execute("DROP TRIGGER fail_learning")
        self.pool.conn.commit()
        self.assertTrue(self.pool.record_probe(self.uid, result))
        self.assertEqual(self.pool.conn.execute(
            "SELECT COUNT(*) FROM probe_log").fetchone()[0], 1)
        self.assertEqual(self.pool.stability_get("proxy6", "fi")["probes_ok"], 1)
        global_row = self.pool.learning_buckets(level="global")[0]
        self.assertEqual(global_row["probes_ok"], 1)

    def test_drop_and_battle_dual_write_are_atomic(self):
        row = self.row()
        self.pool.conn.execute(
            "CREATE TRIGGER fail_learning BEFORE INSERT ON learning_bucket "
            "BEGIN SELECT RAISE(ABORT, 'injected learning failure'); END")
        self.pool.conn.commit()
        with self.assertRaises(pool_mod.PoolDBError):
            self.pool.learning_record_drop(row)
        with self.assertRaises(pool_mod.PoolDBError):
            self.pool.learning_record_battle(row, 60)
        self.assertIsNone(self.pool.stability_get("proxy6", "fi"))
        self.assertEqual(self.pool.learning_buckets(), [])

    def test_production_probe_persists_asn_and_battle_reuses_it(self):
        def fake_curl(args, timeout=probe.CURL_TIMEOUT):
            if probe.IPIFY_URL in args:
                return 0, "5.5.5.5"
            if "%{http_code}" in args:
                return 0, "204"
            return 0, "0.1"

        geo = {"cc": "fi", "alt": "fi", "agree": True}
        with mock.patch.object(probe, "_run_curl", side_effect=fake_curl), \
                mock.patch.object(probe, "geo_country_consensus", return_value=geo), \
                mock.patch.object(probe, "ip_intel", return_value={"asn": "AS64500"}):
            result = probe.probe(self.row(), latency_runs=1)
        self.assertEqual(result["asn"], "AS64500")
        self.assertTrue(self.pool.record_probe(self.uid, result))
        stored = self.row()
        self.assertEqual(stored["asn"], "AS64500")
        self.assertTrue(self.pool.record_probe(self.uid, {
            "ok": False, "tg_ok": False, "geo_agree": None,
            "latency_ms": None, "socks_ok": False, "http_ok": False,
            "exit_ip": None, "asn": None, "disqualified": "no-combo"}))
        stored = self.row()
        self.assertEqual(stored["asn"], "AS64500")
        self.pool.learning_record_drop(stored)
        self.pool.learning_record_battle(stored, 60)
        asn_row = self.pool.learning_buckets(level="asn", asn="AS64500")[0]
        self.assertEqual((asn_row["probes_ok"], asn_row["probes_fail"],
                          asn_row["battle_drops"], asn_row["battle_seconds"]),
                         (1, 1, 1, 60))


class TestLearningShadow(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.pool = pool_mod.Pool(os.path.join(self.tmp.name, "state.db"), server="node2")

    def tearDown(self):
        self.pool.close()
        self.tmp.cleanup()

    def add(self, ext_id, country, host):
        return self.pool.upsert_proxy({
            "provider": "proxy6", "ext_id": ext_id, "ip": host, "host": host,
            "port_http": 8080, "port_socks5": 1080, "user": "u", "password": "p",
            "country": country, "ip_version": 4, "kind": "dedicated",
            "date_end": None, "descr": ""})

    def test_shadow_recommends_better_proxy_and_only_writes_journal(self):
        good, bad = self.add("good", "fi", "1.1.1.1"), self.add("bad", "ng", "2.2.2.2")
        for age in range(10):
            day = (TODAY - datetime.timedelta(days=age)).isoformat()
            self.pool.learning_bump_probe(
                self.pool.get(good), {"ok": True, "tg_ok": True,
                                      "geo_agree": True, "latency_ms": 50}, day=day)
            self.pool.learning_bump_probe(
                self.pool.get(bad), {"ok": False, "tg_ok": False,
                                     "geo_agree": False, "latency_ms": 900}, day=day)
        proxy_before = [dict(row) for row in self.pool.list()]
        event_before = self.pool.conn.execute("SELECT COUNT(*) FROM event").fetchone()[0]
        money_before = self.pool.conn.execute("SELECT COUNT(*) FROM money").fetchone()[0]
        decision = learning.record_shadow_decision(
            self.pool, self.pool.rotation_candidates(),
            {"learning": {"mode": "shadow"}}, current_host="2.2.2.2",
            strategy="speed", now=datetime.datetime(2026, 8, 22, 12, 0))
        self.assertEqual(decision["recommended_uid"], good)
        self.assertEqual(decision["current_uid"], bad)
        self.assertEqual(decision["mode"], "shadow")
        self.assertEqual(len(decision["scores"]), 2)
        self.assertEqual([dict(row) for row in self.pool.list()], proxy_before)
        self.assertEqual(self.pool.conn.execute(
            "SELECT COUNT(*) FROM event").fetchone()[0], event_before)
        self.assertEqual(self.pool.conn.execute(
            "SELECT COUNT(*) FROM money").fetchone()[0], money_before)

    def test_activation_requires_owner_canary_and_30_distinct_days(self):
        cfg = {"learning": {"mode": "canary", "shadow_min_days": 30,
                            "owner_approved": True, "canary_servers": ["node2"]}}
        recommendation = {"formula_version": learning.FORMULA_VERSION,
                          "scores": [], "candidate_count": 0}
        for age in range(29):
            self.pool.record_shadow_decision(
                recommendation, ts=TODAY - datetime.timedelta(days=age))
        status = learning.activation_status(self.pool, cfg, server="node2", now=TODAY)
        self.assertFalse(status["eligible"])
        self.assertIn("shadow-days-29/30", status["blockers"])
        self.pool.record_shadow_decision(
            recommendation, ts=TODAY - datetime.timedelta(days=29))
        self.assertTrue(learning.activation_status(
            self.pool, cfg, server="node2", now=TODAY)["eligible"])
        self.assertFalse(learning.activation_status(
            self.pool, cfg, server="node1", now=TODAY)["eligible"])
        shadow_cfg = {"learning": {**cfg["learning"], "mode": "shadow"}}
        self.assertFalse(learning.activation_status(
            self.pool, shadow_cfg, server="node2", now=TODAY)["eligible"])

    def test_future_dates_do_not_satisfy_shadow_gate(self):
        cfg = {"learning": {"mode": "canary", "shadow_min_days": 30,
                            "owner_approved": True, "canary_servers": ["node2"]}}
        recommendation = {"formula_version": learning.FORMULA_VERSION,
                          "scores": [], "candidate_count": 0}
        for ahead in range(1, 31):
            self.pool.record_shadow_decision(
                recommendation, ts=TODAY + datetime.timedelta(days=ahead))
        status = learning.activation_status(self.pool, cfg, server="node2", now=TODAY)
        self.assertFalse(status["eligible"])
        self.assertEqual(status["coverage"]["days"], 0)

    def test_active_requires_recorded_canary_evidence(self):
        cfg = {"learning": {"mode": "active", "shadow_min_days": 30,
                            "owner_approved": True, "canary_servers": ["node2"]}}
        recommendation = {"formula_version": learning.FORMULA_VERSION,
                          "scores": [], "candidate_count": 0}
        for age in range(30):
            self.pool.record_shadow_decision(
                recommendation, mode="shadow", ts=TODAY - datetime.timedelta(days=age))
        blocked = learning.activation_status(self.pool, cfg, server="node1", now=TODAY)
        self.assertFalse(blocked["eligible"])
        self.assertIn("canary-evidence-required", blocked["blockers"])
        self.pool.record_shadow_decision(
            recommendation, mode="canary", ts=TODAY)
        self.assertTrue(learning.activation_status(
            self.pool, cfg, server="node1", now=TODAY)["eligible"])

    def test_exploration_uses_owned_reserve_and_enforces_daily_limit(self):
        current = self.add("current", "fi", "1.1.1.1")
        reserve = self.add("reserve", "de", "2.2.2.2")
        cfg = {"learning": {"owner_approved": True, "exploration_enabled": True,
                            "exploration_rate": 1.0, "exploration_max_per_day": 1}}
        before = [dict(row) for row in self.pool.list()]
        first = learning.maybe_exploration(
            self.pool, [self.pool.get(current), self.pool.get(reserve),
                        {"uid": "market:not-bought", "host": "3.3.3.3"}],
            cfg=cfg, current_host="1.1.1.1", now=TODAY, rng=lambda: 0.0)
        second = learning.maybe_exploration(
            self.pool, [self.pool.get(current), self.pool.get(reserve)],
            cfg=cfg, current_host="1.1.1.1", now=TODAY, rng=lambda: 0.0)
        self.assertEqual((first["result"], first["selected_uid"]), ("chosen", reserve))
        self.assertEqual((second["result"], second["reason"]), ("denied", "daily-limit"))
        self.assertEqual([row["result"] for row in self.pool.exploration_history()],
                         ["chosen", "denied"])
        self.assertEqual([dict(row) for row in self.pool.list()], before)
        self.assertEqual(self.pool.conn.execute("SELECT COUNT(*) FROM money").fetchone()[0], 0)

    def test_exploration_rejects_synthetic_off_gone_and_current_rows(self):
        current = self.add("current", "fi", "1.1.1.1")
        off = self.add("off", "de", "2.2.2.2")
        gone = self.add("gone", "de", "3.3.3.3")
        self.pool.set_role(off, "off")
        self.pool.conn.execute("UPDATE proxy SET gone=1 WHERE uid=?", (gone,))
        self.pool.conn.commit()
        cfg = {"learning": {"owner_approved": True, "exploration_enabled": True,
                            "exploration_rate": 1.0, "exploration_max_per_day": 1}}
        result = learning.maybe_exploration(
            self.pool, [self.pool.get(current), self.pool.get(off), self.pool.get(gone),
                        {"uid": "market:not-bought", "host": "4.4.4.4"}],
            cfg=cfg, current_host="1.1.1.1", now=TODAY, rng=lambda: 0.0)
        self.assertEqual((result["result"], result["reason"]),
                         ("denied", "no-owned-reserve"))
        self.assertEqual(self.pool.exploration_history(), [])

    def test_concurrent_exploration_claims_only_one_daily_slot(self):
        self.add("current", "fi", "1.1.1.1")
        reserve = self.add("reserve", "de", "2.2.2.2")
        other = pool_mod.Pool(self.pool.db_path, server="node2")
        barrier, results, errors = threading.Barrier(2), [], []
        def claim(instance):
            try:
                barrier.wait()
                results.append(instance.claim_exploration(
                    reserve, "1.1.1.1", max_per_day=1, now=TODAY))
            except Exception as exc:
                errors.append(exc)
        threads = [threading.Thread(target=claim, args=(instance,))
                   for instance in (self.pool, other)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
        other.close()
        self.assertEqual(errors, [])
        self.assertEqual(sorted(item["result"] for item in results), ["chosen", "denied"])

    def test_exploration_purchase_needs_separate_budget_but_has_no_actuator(self):
        base = {"learning": {"owner_approved": True,
                             "exploration_purchase_budget_per_day": 0}}
        denied = learning.exploration_purchase_status(base, estimated_cost=10)
        self.assertFalse(denied["eligible"])
        self.assertIn("separate-budget-required", denied["reason"])
        funded = {"learning": {"owner_approved": True,
                               "exploration_purchase_budget_per_day": 100}}
        self.assertTrue(learning.exploration_purchase_status(
            funded, estimated_cost=40, spent_today=50)["eligible"])
        self.assertFalse(learning.exploration_purchase_status(
            funded, estimated_cost=60, spent_today=50)["eligible"])
        self.assertIn("no exploration buy actuator", denied["note"])

    def test_zero_rate_and_invalid_rng_fail_closed(self):
        self.add("current", "fi", "1.1.1.1")
        reserve = self.add("reserve", "de", "2.2.2.2")
        called = []
        zero = {"learning": {"owner_approved": True, "exploration_enabled": True,
                             "exploration_rate": 0, "exploration_max_per_day": 1}}
        result = learning.maybe_exploration(
            self.pool, [self.pool.get(reserve)], cfg=zero, current_host="1.1.1.1",
            now=TODAY, rng=lambda: called.append(True) or float("nan"))
        self.assertEqual(result["result"], "disabled")
        self.assertIn("sample-rate-zero", result["reason"])
        self.assertEqual(called, [])
        enabled = {"learning": {**zero["learning"], "exploration_rate": 1}}
        for draw in (float("nan"), -0.1, 1.0, float("inf")):
            invalid = learning.maybe_exploration(
                self.pool, [self.pool.get(reserve)], cfg=enabled,
                current_host="1.1.1.1", now=TODAY, rng=lambda draw=draw: draw)
            self.assertEqual((invalid["result"], invalid["reason"]),
                             ("denied", "invalid-rng"))
        self.assertEqual(self.pool.exploration_history(), [])

    def test_active_rejects_canary_that_predates_shadow_qualification(self):
        cfg = {"learning": {"mode": "active", "shadow_min_days": 30,
                            "owner_approved": True, "canary_servers": ["node2"]}}
        recommendation = {"formula_version": learning.FORMULA_VERSION,
                          "scores": [], "candidate_count": 0}
        self.pool.record_shadow_decision(
            recommendation, mode="canary", ts=TODAY - datetime.timedelta(days=100))
        for age in range(30):
            self.pool.record_shadow_decision(
                recommendation, mode="shadow", ts=TODAY - datetime.timedelta(days=age))
        blocked = learning.activation_status(self.pool, cfg, server="node1", now=TODAY)
        self.assertFalse(blocked["eligible"])
        self.assertIn("canary-evidence-required", blocked["blockers"])
        self.pool.record_shadow_decision(
            recommendation, mode="canary", ts=datetime.datetime(2026, 8, 22, 12, 0))
        self.assertTrue(learning.activation_status(
            self.pool, cfg, server="node1", now=TODAY)["eligible"])


if __name__ == "__main__":
    unittest.main()
