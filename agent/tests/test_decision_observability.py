# -*- coding: utf-8 -*-
"""Structured decision events: safe persistence, API projection and UI details."""
import json
import math
import os
import sqlite3
import tempfile
import types
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

import _ctx  # noqa: F401
import pool as pool_mod
import states
from webpanel import server, views


class TestDecisionEventStorage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "state.db")
        self.pool = pool_mod.Pool(self.db, server="test")

    def tearDown(self):
        self.pool.close()
        self.tmp.cleanup()

    def test_roundtrip_is_json_safe_and_never_leaks_raw_column(self):
        payload = {"strategy": "speed", "mode": "auto", "score_breakdown": [],
                   "freshness": {}, "margin": math.inf, "exclusions": [],
                   "reason": "test"}
        self.pool.log_event("strategy-apply", payload=payload)
        event = self.pool.events(1)[0]
        self.assertNotIn("payload_json", event)
        self.assertIsNone(event["decision"]["margin"])

        self.pool.log_event("login", result="ok")
        plain = self.pool.events(1)[0]
        self.assertNotIn("payload_json", plain)
        self.assertIsNone(plain["decision"])

    def test_decision_action_gets_complete_default_shape(self):
        self.pool.log_event("rotate", result="empty", detail="no candidates")
        decision = self.pool.events(1)[0]["decision"]
        self.assertTrue({"strategy", "mode", "score_breakdown", "freshness",
                         "margin", "exclusions", "reason"}.issubset(decision))

    def test_concurrent_events_are_not_lost_on_shared_connection(self):
        total = 64
        with ThreadPoolExecutor(max_workers=16) as executor:
            list(executor.map(lambda number: self.pool.log_event(
                "rotate", actor="auto", result="ok", detail=str(number)), range(total)))
        count = self.pool.conn.execute(
            "SELECT COUNT(*) FROM event WHERE action='rotate'").fetchone()[0]
        self.assertEqual(count, total)

    def test_nonstandard_json_constant_is_quarantined(self):
        self.pool.log_event("rotate", result="ok")
        self.pool.conn.execute(
            "UPDATE event SET payload_json=? WHERE id=(SELECT MAX(id) FROM event)",
            ('{"margin":NaN}',))
        self.pool.conn.commit()
        event = self.pool.events(1)[0]
        self.assertIsNone(event["decision"])
        json.dumps(event, allow_nan=False)

    def test_deeply_nested_corrupt_payload_is_quarantined(self):
        self.pool.log_event("rotate", result="ok")
        nested = "[" * 3000 + "0" + "]" * 3000
        self.pool.conn.execute(
            "UPDATE event SET payload_json=? WHERE id=(SELECT MAX(id) FROM event)",
            (nested,))
        self.pool.conn.commit()
        event = self.pool.events(1)[0]
        self.assertIsNone(event["decision"])
        json.dumps(event, allow_nan=False)

    def test_migrates_existing_event_table_to_schema_six(self):
        self.pool.close()
        os.unlink(self.db)
        conn = sqlite3.connect(self.db)
        conn.execute("CREATE TABLE event(id INTEGER PRIMARY KEY, ts TEXT NOT NULL, "
                     "action TEXT NOT NULL)")
        conn.execute("CREATE TABLE setting(key TEXT PRIMARY KEY, value TEXT)")
        conn.execute("INSERT INTO setting VALUES('schema_version','4')")
        conn.commit()
        conn.close()
        self.pool = pool_mod.Pool(self.db, server="test")
        columns = {row[1] for row in self.pool.conn.execute("PRAGMA table_info(event)")}
        self.assertIn("payload_json", columns)
        self.assertEqual(self.pool.get_setting("schema_version"), "6")


class _JSONHandler:
    def _json(self, code, body, extra=None):
        self.response = (code, body)


class TestDecisionAPI(unittest.TestCase):
    def test_api_projects_decision_but_not_source_ip_or_raw_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            pool = pool_mod.Pool(os.path.join(tmp, "state.db"), server="test")
            pool.log_event("rotate", result="empty", src_ip="192.0.2.55",
                           payload={"strategy": "speed", "mode": "auto",
                                    "score_breakdown": [], "freshness": {},
                                    "margin": None, "exclusions": [], "reason": "none"})
            old_app = server.APP
            server.APP = types.SimpleNamespace(pool=pool)
            try:
                handler = _JSONHandler()
                server.Handler._api_get(handler, "/api/events", {"limit": ["1"]})
                code, body = handler.response
            finally:
                server.APP = old_app
                pool.close()
        self.assertEqual(code, 200)
        event = body["events"][0]
        self.assertEqual(event["decision"]["reason"], "none")
        self.assertNotIn("src_ip", event)
        self.assertNotIn("payload_json", event)

    def test_dashboard_renders_escaped_expandable_json(self):
        page = views.dashboard_page("test", "csrf")
        self.assertIn("<details><summary>", page)
        self.assertIn("JSON.stringify(e.decision,null,2)", page)
        self.assertIn("esc(JSON.stringify", page)


class TestRotationDecisionEvent(unittest.TestCase):
    def test_empty_rotation_records_exclusion_reasons_without_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            sb_path = os.path.join(tmp, "singbox.json")
            with open(sb_path, "w", encoding="utf-8") as handle:
                json.dump({"outbounds": [{"tag": "socks-out", "type": "socks",
                                           "server": "10.0.0.1", "server_port": 1080}]}, handle)
            pool = pool_mod.Pool(os.path.join(tmp, "state.db"), server="test")
            uid = pool.upsert_proxy({
                "provider": "proxy6", "ext_id": "off", "ip": "10.0.0.2",
                "host": "10.0.0.2", "port_http": 8080, "port_socks5": 1080,
                "user": "secret-user", "password": "secret-password", "country": "de",
                "ip_version": 4, "kind": "dedicated", "date_end": None, "descr": ""})
            pool.set_role(uid, "off")
            cfg = {"singbox_config": sb_path, "countries": {"strategy": "speed"}}
            try:
                result = states.try_rotating(cfg, {}, pool, mock.Mock(), lambda *_: None, "auto")
                event = pool.events(1)[0]
            finally:
                pool.close()
        self.assertTrue(result["exhausted"])
        self.assertEqual(event["result"], "empty")
        self.assertEqual(event["decision"]["exclusions"],
                         [{"reason": "disabled", "uid": uid}])
        encoded = json.dumps(event["decision"])
        self.assertNotIn("secret-user", encoded)
        self.assertNotIn("secret-password", encoded)

    def test_successful_rotation_keeps_all_ranked_alternatives(self):
        with tempfile.TemporaryDirectory() as tmp:
            sb_path = os.path.join(tmp, "singbox.json")
            with open(sb_path, "w", encoding="utf-8") as handle:
                json.dump({"outbounds": [{"tag": "socks-out", "type": "socks",
                                           "server": "10.0.0.1", "server_port": 1080}]}, handle)
            pool = pool_mod.Pool(os.path.join(tmp, "state.db"), server="test")
            uids = []
            for provider, ext_id, host in (("proxy6", "a", "10.0.0.2"),
                                           ("proxywing", "b", "10.0.0.3")):
                uids.append(pool.upsert_proxy({
                    "provider": provider, "ext_id": ext_id, "ip": host, "host": host,
                    "port_http": 8080, "port_socks5": 1080, "user": "u", "password": "p",
                    "country": "de", "ip_version": 4, "kind": "dedicated",
                    "date_end": None, "descr": ""}))
            cfg = {"singbox_config": sb_path, "countries": {"strategy": "speed"}}
            apply_result = {"ok": True, "new_ip": "10.0.0.2",
                            "verify": {"egress_ip": "198.51.100.2", "exit_cc": "de",
                                       "tg_code": "200"}}
            probe_result = {"ok": True, "disqualified": None, "score": 100.0}
            try:
                with mock.patch.object(states, "_probe", return_value=probe_result), \
                     mock.patch.object(states.apply_mod, "apply_candidate",
                                       return_value=apply_result):
                    result = states.try_rotating(
                        cfg, {"proxy6": object(), "proxywing": object()}, pool,
                        mock.Mock(), lambda *_: None, "auto")
                event = pool.events(1)[0]
            finally:
                pool.close()
        self.assertTrue(result["ok"])
        self.assertEqual({item["uid"] for item in event["decision"]["score_breakdown"]},
                         set(uids))


if __name__ == "__main__":
    unittest.main()
