# -*- coding: utf-8 -*-
"""Refresh must keep SQLite usable across slow providers and failed merges."""
import os
import tempfile
import unittest

import _ctx  # noqa: F401
import pool


def proxy(provider, ident, host="192.0.2.1"):
    return {"provider": provider, "ext_id": ident, "host": host, "ip": host,
            "country": "de", "port_socks5": 1080}


class Provider:
    def __init__(self, rows, callback=None):
        self.rows = rows
        self.callback = callback

    def list(self):
        if self.callback:
            self.callback()
        return self.rows


class TestRefreshAtomic(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.pool = pool.Pool(os.path.join(self.tmp.name, "state.db"))

    def tearDown(self):
        self.pool.close()
        self.tmp.cleanup()

    def test_next_provider_network_call_does_not_hold_database_writer(self):
        # A second process must be able to log a heartbeat during the next API call.
        observer = pool.Pool(self.pool.db_path)
        observer.conn.execute("PRAGMA busy_timeout=1")
        def during_network():
            observer.run_transaction(lambda conn: conn.execute(
                "INSERT INTO setting(key,value) VALUES('concurrent-heartbeat','ok')"),
                attempts=1)
        try:
            report = self.pool.refresh({
                "proxy6": Provider([proxy("proxy6", "a")]),
                "proxyline": Provider([proxy("proxyline", "b")], during_network)})
            self.assertEqual(report["errors"], {})
            self.assertEqual(observer.get_setting("concurrent-heartbeat"), "ok")
        finally:
            observer.close()

    def test_merge_failure_rolls_back_all_rows_and_leaves_connection_usable(self):
        uid = self.pool.upsert_proxy(proxy("proxy6", "a"))
        self.pool.conn.execute("""CREATE TRIGGER reject_bad BEFORE INSERT ON proxy
            WHEN NEW.ext_id='bad' BEGIN SELECT RAISE(ABORT, 'injected failure'); END""")
        self.pool.conn.commit()
        try:
            self.pool.refresh({"proxy6": Provider([
                proxy("proxy6", "a", "192.0.2.99"), proxy("proxy6", "bad")])})
        except Exception:
            pass
        else:
            self.fail("injected database failure must be reported")
        self.assertFalse(self.pool.conn.in_transaction)
        self.assertEqual(self.pool.get(uid)["host"], "192.0.2.1")
        self.pool.log_event("after-failed-refresh", result="ok")
        reopened = pool.Pool(self.pool.db_path)
        try:
            self.assertEqual(reopened.get(uid)["host"], "192.0.2.1")
        finally:
            reopened.close()

    def test_invalid_listing_is_rejected_before_changes_and_other_provider_continues(self):
        uid = self.pool.upsert_proxy(proxy("proxy6", "a"))
        report = self.pool.refresh({
            "proxy6": Provider([proxy("proxy6", "a", "192.0.2.99"), {}]),
            "proxyline": Provider([proxy("proxyline", "b")])})
        self.assertIn("proxy6", report["errors"])
        self.assertEqual(self.pool.get(uid)["host"], "192.0.2.1")
        self.assertIsNotNone(self.pool.get("proxyline:b"))
        self.assertFalse(self.pool.conn.in_transaction)

    def test_non_string_ext_id_is_rejected_before_writer_and_next_provider_continues(self):
        uid = self.pool.upsert_proxy(proxy("proxy6", "a"))
        report = self.pool.refresh({
            "proxy6": Provider([
                proxy("proxy6", "a", "192.0.2.99"), proxy("proxy6", [])]),
            "proxyline": Provider([proxy("proxyline", "b")]),
        })
        self.assertIn("proxy6", report["errors"])
        self.assertEqual(self.pool.get(uid)["host"], "192.0.2.1")
        self.assertIsNotNone(self.pool.get("proxyline:b"))
        self.assertFalse(self.pool.conn.in_transaction)

    def test_provider_cannot_overwrite_another_provider_listing(self):
        uid = self.pool.upsert_proxy(proxy("proxyline", "b"))
        report = self.pool.refresh({"proxy6": Provider([
            proxy("proxyline", "b", "192.0.2.99")])})
        self.assertIn("proxy6", report["errors"])
        self.assertEqual(self.pool.get(uid)["host"], "192.0.2.1")


if __name__ == "__main__":
    unittest.main()
