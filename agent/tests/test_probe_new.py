# -*- coding: utf-8 -*-
"""Проверка новых каналов после смены ключа (жалоба владельца 19.08).

Раньше панель после POST /api/key только подтягивала пул: каналы нового кабинета
висели «не проверялся» до двухчасового крона, превью стратегий и автоматика видели
их слепыми. Теперь фоновый кик зовёт `pool-refresh --probe-new`, а агент пробует
ИМЕННО непробованные каналы в порядке текущей стратегии — денег не тратит
(докупка N+1 остаётся дорожкой --probe).
"""
import os
import sys
import tempfile
import unittest
from unittest import mock

from _ctx import PANEL_DIR
import agent
import pool as pool_mod

sys.path.insert(0, os.path.join(PANEL_DIR, "webpanel"))
import server  # noqa: E402


def _norm(ext_id, country, host):
    return {"provider": "proxy6", "ext_id": str(ext_id), "ip": host, "host": host,
            "port_http": 8080, "port_socks5": 1080, "user": "u", "password": "p",
            "country": country, "ip_version": 4, "kind": "dedicated",
            "date_end": None, "descr": ""}


class TestProbeNewChannels(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.pool = pool_mod.Pool(os.path.join(self.tmp.name, "state.db"), server="test")
        self.cfg = {"server": "test"}

    def tearDown(self):
        self.pool.close()
        self.tmp.cleanup()

    def test_probes_only_unprobed_in_strategy_order(self):
        self.pool.upsert_proxy(_norm(1, "ng", "1.1.1.1"))     # сырой, страна послабее
        self.pool.upsert_proxy(_norm(2, "de", "2.2.2.2"))     # сырой, страна надёжная
        probed = self.pool.upsert_proxy(_norm(3, "fi", "3.3.3.3"))
        self.pool.conn.execute("UPDATE proxy SET last_probe_at=? WHERE uid=?",
                               (pool_mod.now_iso(), probed))
        self.pool.conn.commit()
        off = self.pool.upsert_proxy(_norm(4, "se", "4.4.4.4"))
        self.pool.set_role(off, "off")

        calls = []

        def fake_probe(p, cfg, providers, row, current_host, background=False):
            calls.append((row["uid"], background))
            return {"ok": True}

        with mock.patch.object(agent, "_probe_one", side_effect=fake_probe):
            ok, total = agent.probe_new_channels(self.pool, self.cfg, {}, None,
                                                 log=lambda m: None)
        self.assertEqual((ok, total), (2, 2))
        # только сырые auto-каналы; порядок — по текущей стратегии (de раньше ng),
        # уже проверенный и off не перегоняются
        self.assertEqual([c[0] for c in calls], ["proxy6:2", "proxy6:1"])
        # F5: как у крона — одиночный провал новичка не качает fail_count
        self.assertTrue(all(bg for _, bg in calls))

    def test_no_new_channels_is_quiet(self):
        # пустой пул: пробовать нечего, событие в журнал не пишется
        with mock.patch.object(agent, "_probe_one") as mp:
            ok, total = agent.probe_new_channels(self.pool, self.cfg, {}, None,
                                                 log=lambda m: None)
        self.assertEqual((ok, total), (0, 0))
        mp.assert_not_called()
        n = self.pool.conn.execute(
            "SELECT COUNT(*) FROM event WHERE action='probe-new'").fetchone()[0]
        self.assertEqual(n, 0)

    def test_event_logged_with_result(self):
        self.pool.upsert_proxy(_norm(1, "de", "2.2.2.2"))
        with mock.patch.object(agent, "_probe_one", return_value={"ok": False}):
            agent.probe_new_channels(self.pool, self.cfg, {}, None, log=lambda m: None)
        row = self.pool.conn.execute(
            "SELECT actor, result FROM event WHERE action='probe-new'").fetchone()
        self.assertEqual((row[0], row[1]), ("auto", "0/1 ok"))


class TestPoolRefreshKickContract(unittest.TestCase):
    def test_kick_asks_probe_new(self):
        # контракт панель→агент: смена ключа обязана не только подтянуть пул,
        # но и проверить новые каналы — иначе они слепы до двухчасового крона
        calls = []
        with mock.patch.object(
                server, "_run_agent",
                side_effect=lambda a, timeout=240: (calls.append(list(a)), (0, ""))[1]):
            server._pool_refresh_kick()
        self.assertEqual(calls, [["pool-refresh", "--probe-new"]])


if __name__ == "__main__":
    unittest.main()
