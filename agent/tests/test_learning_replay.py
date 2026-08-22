# -*- coding: utf-8 -*-
import datetime
import hashlib
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

import _ctx  # noqa: F401
import agent
import pool as pool_mod
import replay


def probe_row(row_id, ts, uid, ok, latency, current=False, provider="proxy6", country="fi"):
    return {"id": row_id, "ts": ts, "uid": uid, "provider": provider,
            "country": country, "exit_cc": country, "geo_agree": 1,
            "ok": 1 if ok else 0, "latency_ms": latency, "tg_ok": 1 if ok else 0,
            "is_current": 1 if current else 0, "strategy": "speed"}


class TestOfflineReplay(unittest.TestCase):
    def snapshot(self):
        return {
            "since": "2026-08-01 00:00:00", "until": "2026-08-22 23:59:59",
            "probe_log": [
                probe_row(1, "2026-08-20 00:00:00", "proxy6:a", True, 200, True),
                probe_row(2, "2026-08-20 00:00:00", "proxy6:b", True, 50),
                probe_row(3, "2026-08-20 01:00:00", "proxy6:a", False, None, True),
                probe_row(4, "2026-08-20 01:00:00", "proxy6:b", True, 60),
                probe_row(5, "2026-08-20 02:00:00", "proxy6:a", False, None, True),
                probe_row(6, "2026-08-20 02:00:00", "proxy6:b", True, 70),
            ],
            "event": [{"id": 1, "ts": "2026-08-20 01:05:00", "action": "rotate",
                       "result": "ok", "to_uid": "proxy6:b"}],
            "money": [{"id": 1, "ts": "2026-08-10 00:00:00", "op": "buy",
                       "price": 28.0, "currency": "RUB"}],
        }

    def test_report_contains_required_comparison_metrics(self):
        report = replay.run(self.snapshot())
        self.assertEqual(report["actual"]["switches"], 1)
        self.assertEqual(report["actual"]["spend_by_currency"], {"RUB": 28.0})
        self.assertEqual(report["actual"]["latency"]["mean_ms"], 200.0)
        self.assertEqual(report["actual"]["downtime_share"], 0.5)
        self.assertEqual(report["v2"]["incremental_spend_by_currency"], {})
        self.assertIn("extra_switches_vs_actual", report["v2"])
        self.assertIn("p95_ms", report["v2"]["latency"])
        self.assertIn("share", report["v2"]["wrong_choice"])
        self.assertTrue(report["trace"]["choices"])
        self.assertGreaterEqual(len(report["limitations"]), 3)

    def test_future_probe_does_not_change_first_historical_choice(self):
        base = self.snapshot()
        first = replay.run(base)["trace"]["choices"][0]
        extended = {**base, "probe_log": base["probe_log"] + [
            probe_row(7, "2026-08-21 00:00:00", "proxy6:a", True, 1, True)]}
        self.assertEqual(replay.run(extended)["trace"]["choices"][0], first)

    def test_wrong_choice_is_judged_by_next_probe(self):
        snapshot = self.snapshot()
        snapshot["probe_log"][3] = probe_row(
            4, "2026-08-20 01:00:00", "proxy6:b", False, None)
        report = replay.run(snapshot)
        self.assertGreaterEqual(report["v2"]["wrong_choice"]["evaluated"], 1)
        self.assertGreaterEqual(report["v2"]["wrong_choice"]["wrong"], 1)

    def test_unchanged_v2_channel_still_has_latency_and_downtime_timeline(self):
        snapshot = {"since": "2026-08-20 00:00:00", "until": "2026-08-20 03:00:00",
                    "probe_log": [
                        probe_row(1, "2026-08-20 00:00:00", "proxy6:a", True, 10, True),
                        probe_row(2, "2026-08-20 01:00:00", "proxy6:a", False, None, True),
                        probe_row(3, "2026-08-20 02:00:00", "proxy6:a", False, None, True)],
                    "event": [], "money": []}
        report = replay.run(snapshot)
        self.assertEqual(report["trace"]["choices"], [])
        self.assertEqual(report["v2"]["latency"], {
            "samples": 1, "mean_ms": 10.0, "p95_ms": 10.0})
        self.assertEqual(report["v2"]["downtime_share"], 0.5)

    def test_mixed_timestamps_and_malformed_latency_are_tolerated(self):
        snapshot = {"since": None, "until": None, "event": [], "money": [],
                    "probe_log": [
                        probe_row(1, "2026-08-20 00:00:00", "proxy6:a", True,
                                  "broken", True),
                        probe_row(2, "2026-08-20T01:00:00Z", "proxy6:a", True,
                                  20, True)]}
        report = replay.run(snapshot)
        self.assertEqual(report["actual"]["latency"], {
            "samples": 1, "mean_ms": 20.0, "p95_ms": 20.0})
        self.assertEqual(report["v2"]["latency"]["samples"], 1)

    def test_spend_is_grouped_by_currency_without_conversion(self):
        snapshot = {"since": None, "until": None, "probe_log": [], "event": [],
                    "money": [
                        {"price": 100, "currency": "RUB"},
                        {"price": 2, "currency": "usd"},
                        {"price": 3, "currency": "EUR"}]}
        report = replay.run(snapshot)
        expected = {"EUR": 3.0, "RUB": 100.0, "USD": 2.0}
        self.assertEqual(report["actual"]["spend_by_currency"], expected)
        self.assertEqual(report["v2"]["spend_by_currency"], expected)


class TestReplayReadOnly(unittest.TestCase):
    def test_load_sqlite_does_not_modify_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "state.db")
            pool = pool_mod.Pool(path, server="test")
            uid = pool.upsert_proxy({
                "provider": "proxy6", "ext_id": "1", "ip": "1.1.1.1", "host": "1.1.1.1",
                "port_http": 8080, "port_socks5": 1080, "user": "u", "password": "p",
                "country": "fi", "ip_version": 4, "kind": "dedicated",
                "date_end": None, "descr": ""})
            pool.record_probe(uid, {"ok": True, "tg_ok": True, "geo_agree": True,
                                    "latency_ms": 50, "socks_ok": True})
            pool.close()
            directory_before = sorted(os.listdir(tmp))
            with open(path, "rb") as f:
                before = hashlib.sha256(f.read()).hexdigest()
            snapshot = replay.load_sqlite(
                path, days=90, now=datetime.datetime.now() + datetime.timedelta(days=1))
            report = replay.run(snapshot)
            with open(path, "rb") as f:
                after = hashlib.sha256(f.read()).hexdigest()
            self.assertEqual(after, before)
            self.assertEqual(sorted(os.listdir(tmp)), directory_before)
            self.assertEqual(len(snapshot["probe_log"]), 1)
            self.assertIn("actual", report)

    def test_active_wal_is_copied_without_touching_original_sidecars(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "state.db")
            pool = pool_mod.Pool(path, server="test")
            uid = pool.upsert_proxy({
                "provider": "proxy6", "ext_id": "1", "ip": "1.1.1.1", "host": "1.1.1.1",
                "port_http": 8080, "port_socks5": 1080, "user": "u", "password": "p",
                "country": "fi", "ip_version": 4, "kind": "dedicated",
                "date_end": None, "descr": ""})
            pool.record_probe(uid, {"ok": True, "tg_ok": True, "latency_ms": 10})
            before = {name: (os.path.getsize(os.path.join(tmp, name)),
                             os.stat(os.path.join(tmp, name)).st_mtime_ns)
                      for name in os.listdir(tmp)}
            snapshot = replay.load_sqlite(
                path, days=90, now=datetime.datetime.now() + datetime.timedelta(days=1))
            after = {name: (os.path.getsize(os.path.join(tmp, name)),
                            os.stat(os.path.join(tmp, name)).st_mtime_ns)
                     for name in os.listdir(tmp)}
            pool.close()
            self.assertEqual(after, before)
            self.assertEqual(len(snapshot["probe_log"]), 1)

    def test_checkpoint_between_main_and_wal_copy_retries_consistently(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "state.db")
            pool = pool_mod.Pool(path, server="test")
            uid = pool.upsert_proxy({
                "provider": "proxy6", "ext_id": "1", "ip": "1.1.1.1", "host": "1.1.1.1",
                "port_http": 8080, "port_socks5": 1080, "user": "u", "password": "p",
                "country": "fi", "ip_version": 4, "kind": "dedicated",
                "date_end": None, "descr": ""})
            pool.record_probe(uid, {"ok": True, "tg_ok": True, "latency_ms": 10})
            self.assertGreater(os.path.getsize(path + "-wal"), 0)
            original, triggered = replay.shutil.copy2, []
            def racing_copy(source, destination):
                result = original(source, destination)
                if os.path.abspath(source) == os.path.abspath(path) and not triggered:
                    triggered.append(True)
                    pool.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
                return result
            with mock.patch.object(replay.shutil, "copy2", side_effect=racing_copy):
                snapshot = replay.load_sqlite(
                    path, days=90, now=datetime.datetime.now() + datetime.timedelta(days=1))
            source_count = pool.conn.execute("SELECT COUNT(*) FROM probe_log").fetchone()[0]
            pool.close()
            self.assertEqual(triggered, [True])
            self.assertEqual(source_count, 1)
            self.assertEqual(len(snapshot["probe_log"]), source_count)

    def test_commit_after_zero_wal_check_is_not_missed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "state.db")
            pool = pool_mod.Pool(path, server="test")
            uid = pool.upsert_proxy({
                "provider": "proxy6", "ext_id": "1", "ip": "1.1.1.1", "host": "1.1.1.1",
                "port_http": 8080, "port_socks5": 1080, "user": "u", "password": "p",
                "country": "fi", "ip_version": 4, "kind": "dedicated",
                "date_end": None, "descr": ""})
            pool.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            self.assertEqual(os.path.getsize(path + "-wal"), 0)
            original, triggered = replay.shutil.copy2, []
            def racing_copy(source, destination):
                result = original(source, destination)
                if os.path.abspath(source) == os.path.abspath(path) and not triggered:
                    triggered.append(True)
                    pool.record_probe(uid, {"ok": True, "tg_ok": True, "latency_ms": 10})
                return result
            with mock.patch.object(replay.shutil, "copy2", side_effect=racing_copy):
                snapshot = replay.load_sqlite(
                    path, days=90, now=datetime.datetime.now() + datetime.timedelta(days=1))
            source_count = pool.conn.execute("SELECT COUNT(*) FROM probe_log").fetchone()[0]
            pool.close()
            self.assertEqual(triggered, [True])
            self.assertEqual(source_count, 1)
            self.assertEqual(len(snapshot["probe_log"]), source_count)

    def test_cli_does_not_migrate_or_backup_legacy_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "state.db")
            pool_mod.Pool(db, server="test").close()
            config = os.path.join(tmp, "config.json")
            with open(config, "w", encoding="utf-8") as handle:
                json.dump({"config_schema_version": 0, "db": db}, handle)
            with open(config, "rb") as handle:
                before = handle.read()
            with redirect_stdout(io.StringIO()):
                rc = agent.main(["--config", config, "learning-replay", "--days", "1"])
            with open(config, "rb") as handle:
                after = handle.read()
            self.assertEqual(rc, 0)
            self.assertEqual(after, before)
            self.assertEqual([name for name in os.listdir(tmp) if ".schema-v" in name], [])


if __name__ == "__main__":
    unittest.main()
