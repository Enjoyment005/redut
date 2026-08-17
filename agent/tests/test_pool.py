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
        # П9 (роли v2): оба провайдера по умолчанию auto — деление на «резерв» умерло
        self.pool.refresh({"proxy6": FakeProvider("proxy6", p6_items()),
                           "proxyline": FakeProvider("proxyline", pl_items())})
        self.assertEqual(self.pool.get("proxy6:21")["role"], "auto")
        self.assertEqual(self.pool.get("proxyline:12345")["role"], "auto")

    def test_merge_preserves_role_and_marks_gone(self):
        items = p6_items()
        self.pool.refresh({"proxy6": FakeProvider("proxy6", items)})
        self.pool.set_role("proxy6:21", "off")
        # второй refresh: запись 21 пропала из выдачи, у 11 сменился пароль
        rest = [dict(it) for it in items if it["ext_id"] != "21"]
        for it in rest:
            if it["ext_id"] == "11":
                it["password"] = "новый"
        self.pool.refresh({"proxy6": FakeProvider("proxy6", rest)})
        gone_row = self.pool.get("proxy6:21")
        self.assertEqual(gone_row["gone"], 1, "пропавшие помечаются gone, не удаляются")
        self.assertEqual(gone_row["role"], "off", "роль переживает merge")
        self.assertEqual(self.pool.get("proxy6:11")["password"], "новый")
        # третий refresh: 21 вернулся -> gone снимается, роль всё ещё off
        self.pool.refresh({"proxy6": FakeProvider("proxy6", items)})
        back = self.pool.get("proxy6:21")
        self.assertEqual(back["gone"], 0)
        self.assertEqual(back["role"], "off")

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

    def test_candidates_exclude_off_and_gone(self):
        self.pool.refresh({"proxy6": FakeProvider("proxy6", p6_items())})
        self.pool.set_role("proxy6:11", "off")
        uids = {r["uid"] for r in self.pool.candidates()}
        self.assertNotIn("proxy6:11", uids, "off автоматика не трогает (П9)")
        self.assertIn("proxy6:21", uids)

    def test_bad_role_rejected(self):
        self.pool.refresh({"proxy6": FakeProvider("proxy6", p6_items())})
        with self.assertRaises(ValueError):
            self.pool.set_role("proxy6:21", "admin'; DROP TABLE proxy;--")

    def test_old_roles_rejected_now(self):
        # старых ролей больше нет: селектор и API принимают только auto|off
        self.pool.refresh({"proxy6": FakeProvider("proxy6", p6_items())})
        for role in ("chrome", "reserve", "vpn-ru", "vpn-node1"):
            with self.assertRaises(ValueError):
                self.pool.set_role("proxy6:21", role)

    def test_events_written(self):
        self.pool.refresh({"proxy6": FakeProvider("proxy6", p6_items())})
        n = self.pool.conn.execute("SELECT COUNT(*) FROM event WHERE action='pool-refresh'").fetchone()[0]
        self.assertEqual(n, 1)


class TestRolesV2Migration(unittest.TestCase):
    """П9: миграция ролей к auto|off — снапшот, маркер, идемпотентность."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmpdir.name, "state.db")

    def tearDown(self):
        self.tmpdir.cleanup()

    def seed_old_roles(self):
        """База «старой сборки»: роли из шести, маркера roles_v2 нет."""
        p = pool_mod.Pool(self.db, server="test")
        p.refresh({"proxy6": FakeProvider("proxy6", p6_items()),
                   "proxyline": FakeProvider("proxyline", pl_items())})
        p.conn.execute("UPDATE proxy SET role='chrome' WHERE uid='proxy6:21'")
        p.conn.execute("UPDATE proxy SET role='reserve' WHERE uid='proxyline:12345'")
        p.conn.execute("UPDATE proxy SET role='vpn-ru' WHERE uid='proxy6:11'")
        p.conn.execute("DELETE FROM setting WHERE key='roles_v2'")
        p.conn.commit()
        p.close()

    def test_migrates_and_snapshots(self):
        self.seed_old_roles()
        p = pool_mod.Pool(self.db, server="test")     # коннект = миграция
        self.assertEqual(p.get("proxy6:21")["role"], "off", "chrome -> off")
        self.assertEqual(p.get("proxyline:12345")["role"], "auto", "reserve -> auto")
        self.assertEqual(p.get("proxy6:11")["role"], "auto", "vpn-* -> auto")
        self.assertEqual(p.get_setting("roles_v2"), "1")
        self.assertTrue(os.path.exists(self.db + ".pre-roles-v2"),
                        "миграция необратима — снапшот обязателен")
        n = p.conn.execute(
            "SELECT COUNT(*) FROM event WHERE action='role-migrate'").fetchone()[0]
        self.assertEqual(n, 1)
        p.close()
        # снапшот содержит СТАРЫЕ роли
        snap = sqlite3.connect(self.db + ".pre-roles-v2")
        old = snap.execute("SELECT role FROM proxy WHERE uid='proxy6:21'").fetchone()[0]
        snap.close()
        self.assertEqual(old, "chrome")

    def test_idempotent_by_marker(self):
        self.seed_old_roles()
        pool_mod.Pool(self.db, server="test").close()
        os.unlink(self.db + ".pre-roles-v2")
        p = pool_mod.Pool(self.db, server="test")     # повторный коннект
        self.assertFalse(os.path.exists(self.db + ".pre-roles-v2"),
                         "по маркеру миграция не гоняется повторно")
        n = p.conn.execute(
            "SELECT COUNT(*) FROM event WHERE action='role-migrate'").fetchone()[0]
        self.assertEqual(n, 1, "событие пишется один раз")
        p.close()

    def test_fresh_db_no_snapshot_no_event(self):
        p = pool_mod.Pool(self.db, server="test")
        self.assertEqual(p.get_setting("roles_v2"), "1")
        self.assertFalse(os.path.exists(self.db + ".pre-roles-v2"),
                         "нечего мигрировать — нечего и снапшотить")
        n = p.conn.execute(
            "SELECT COUNT(*) FROM event WHERE action='role-migrate'").fetchone()[0]
        self.assertEqual(n, 0, "событие только при rowcount > 0")
        p.close()


class TestRefreshActiveCleanup(unittest.TestCase):
    """П7 (🔴 C2): уборка осиротевших провайдеров — по ключам на диске, не по словарю."""

    def setUp(self):
        fd, self.db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.pool = pool_mod.Pool(self.db, server="test")
        self.pool.refresh({"proxy6": FakeProvider("proxy6", p6_items()),
                           "proxyline": FakeProvider("proxyline", pl_items())})

    def tearDown(self):
        self.pool.close()
        os.unlink(self.db)

    def alive_providers(self):
        return {r["provider"] for r in self.pool.list(include_gone=False)}

    def test_subset_refresh_does_not_bury_other_provider(self):
        # кейс 🔴 C2: покупка у proxy6 зовёт refresh({"proxy6": …}) БЕЗ active —
        # строки ProxyLine обязаны остаться живыми
        self.pool.refresh({"proxy6": FakeProvider("proxy6", p6_items())})
        self.assertIn("proxyline", self.alive_providers())

    def test_active_both_keys_keeps_both(self):
        # покупка при живых двух ключах: даже если active передали — оба живы
        self.pool.refresh({"proxy6": FakeProvider("proxy6", p6_items())},
                          active={"proxy6", "proxyline"})
        self.assertIn("proxyline", self.alive_providers())

    def test_orphan_provider_marked_gone(self):
        # ключ ProxyLine удалён: полный refresh с active={proxy6} хоронит его строки
        s = self.pool.refresh({"proxy6": FakeProvider("proxy6", p6_items())},
                              active={"proxy6"})
        self.assertNotIn("proxyline", self.alive_providers())
        self.assertIn("proxy6", self.alive_providers())
        self.assertGreater(s["stale"].get("proxyline", 0), 0)

    def test_provider_error_with_key_not_buried(self):
        # ошибка API при ЖИВОМ ключе — не повод хоронить кэш (§10)
        s = self.pool.refresh({"proxy6": FakeProvider("proxy6", error=RuntimeError("API лёг")),
                               "proxyline": FakeProvider("proxyline", pl_items())},
                              active={"proxy6", "proxyline"})
        self.assertIn("proxy6", self.alive_providers())
        self.assertIn("proxy6", s["errors"])
        self.assertEqual(s["stale"], {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
