# -*- coding: utf-8 -*-
"""SQLite-кэш: идемпотентная миграция, merge с gone, сохранность ролей."""
import os
import sqlite3
import tempfile
import unittest

import _ctx
import pool as pool_mod
from providers.proxy6 import norm_proxy6
from providers.proxyline import norm_proxyline


class FakeProvider:
    """Провайдер-заглушка: отдаёт заранее заданные нормализованные записи."""
    def __init__(self, name, items=None, error=None):
        self.name = name
        self._items = items or []
        self._error = error

    def list(self):
        if self._error:
            raise self._error
        return self._items


def p6_items():
    data = _ctx.fixture("proxy6_getproxy.json")
    return [n for n in (norm_proxy6(it) for it in data["list"].values()) if n]


def pl_items():
    return [norm_proxyline(x) for x in _ctx.fixture("proxyline_proxies.json")["results"]]


class TestPool(unittest.TestCase):
    def setUp(self):
        fd, self.db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.pool = pool_mod.Pool(self.db, server="test")

    def tearDown(self):
        self.pool.close()
        os.unlink(self.db)

    def test_migration_idempotent(self):
        # повторная миграция (в т.ч. на живой базе с данными) ничего не ломает
        self.pool.refresh({"proxy6": FakeProvider("proxy6", p6_items())})
        before = self.pool.list(include_gone=True)
        pool_mod.migrate(self.pool.conn)
        pool_mod.migrate(self.pool.conn)
        self.assertEqual(self.pool.list(include_gone=True), before)
        tables = {r[0] for r in self.pool.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertLessEqual({"proxy", "event", "money", "setting"}, tables)

    def test_uid_format(self):
        self.pool.refresh({"proxy6": FakeProvider("proxy6", p6_items()),
                           "proxyline": FakeProvider("proxyline", pl_items())})
        uids = {r["uid"] for r in self.pool.list(include_gone=True)}
        self.assertIn("proxy6:21", uids)
        self.assertIn("proxyline:12345", uids)

    def test_default_roles(self):
        self.pool.refresh({"proxy6": FakeProvider("proxy6", p6_items()),
                           "proxyline": FakeProvider("proxyline", pl_items())})
        self.assertEqual(self.pool.get("proxy6:21")["role"], "auto")
        self.assertEqual(self.pool.get("proxyline:12345")["role"], "reserve",
                         "ProxyLine — статический резерв (§5)")

    def test_merge_preserves_role_and_marks_gone(self):
        items = p6_items()
        self.pool.refresh({"proxy6": FakeProvider("proxy6", items)})
        self.pool.set_role("proxy6:21", "chrome")
        # второй refresh: запись 21 пропала из выдачи, у 11 сменился пароль
        rest = [dict(it) for it in items if it["ext_id"] != "21"]
        for it in rest:
            if it["ext_id"] == "11":
                it["password"] = "новый"
        self.pool.refresh({"proxy6": FakeProvider("proxy6", rest)})
        gone_row = self.pool.get("proxy6:21")
        self.assertEqual(gone_row["gone"], 1, "пропавшие помечаются gone, не удаляются")
        self.assertEqual(gone_row["role"], "chrome", "роль переживает merge")
        self.assertEqual(self.pool.get("proxy6:11")["password"], "новый")
        # третий refresh: 21 вернулся -> gone снимается, роль всё ещё chrome
        self.pool.refresh({"proxy6": FakeProvider("proxy6", items)})
        back = self.pool.get("proxy6:21")
        self.assertEqual(back["gone"], 0)
        self.assertEqual(back["role"], "chrome")

    def test_provider_error_keeps_cache(self):
        self.pool.refresh({"proxy6": FakeProvider("proxy6", p6_items())})
        summary = self.pool.refresh({"proxy6": FakeProvider("proxy6", error=RuntimeError("API лёг"))})
        self.assertIn("proxy6", summary["errors"])
        rows = self.pool.list(include_gone=False)
        self.assertTrue(rows, "при недоступном API работаем на кэше — записи не gone (§10)")

    def test_probe_recording_and_fail_counter(self):
        self.pool.refresh({"proxy6": FakeProvider("proxy6", p6_items())})
        uid = "proxy6:21"
        self.pool.record_probe(uid, {"ok": False})
        self.pool.record_probe(uid, {"ok": False})
        self.assertEqual(self.pool.get(uid)["fail_count"], 2)
        self.pool.record_probe(uid, {"ok": True, "socks_ok": True, "http_ok": True,
                                     "tg_ok": True, "exit_ip": "1.2.3.4", "exit_cc": "fi",
                                     "latency_ms": 120, "score": 130.0})
        row = self.pool.get(uid)
        self.assertEqual(row["fail_count"], 0, "успех сбрасывает счётчик провалов")
        self.assertEqual(row["exit_cc"], "fi")
        self.assertEqual(row["score"], 130.0)

    def test_candidates_exclude_off_chrome_gone(self):
        self.pool.refresh({"proxy6": FakeProvider("proxy6", p6_items())})
        self.pool.set_role("proxy6:11", "off")
        self.pool.set_role("proxy6:14", "chrome")
        uids = {r["uid"] for r in self.pool.candidates()}
        self.assertNotIn("proxy6:11", uids)
        self.assertNotIn("proxy6:14", uids, "chrome автоматика не трогает (§5)")
        self.assertIn("proxy6:21", uids)

    def test_bad_role_rejected(self):
        self.pool.refresh({"proxy6": FakeProvider("proxy6", p6_items())})
        with self.assertRaises(ValueError):
            self.pool.set_role("proxy6:21", "admin'; DROP TABLE proxy;--")

    def test_events_written(self):
        self.pool.refresh({"proxy6": FakeProvider("proxy6", p6_items())})
        n = self.pool.conn.execute("SELECT COUNT(*) FROM event WHERE action='pool-refresh'").fetchone()[0]
        self.assertEqual(n, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
