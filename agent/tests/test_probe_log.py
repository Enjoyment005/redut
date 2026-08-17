# -*- coding: utf-8 -*-
"""Пакет E (П5/П6-фундамент): журнал замеров probe_log + retention + гарантия
«проба не зависит от стратегии».

record_probe ПЕРЕТИРАЕТ строку proxy — probe_log единственный, кто помнит
«сколько раз падал за неделю». Retention: probe_log 90 дн, event 180 дн,
money вечно; prune не чаще раза в сутки.
"""
import datetime
import inspect
import os
import tempfile
import unittest

import _ctx      # noqa: F401
import pool as pool_mod
import probe


def _iso(days_ago):
    return (datetime.datetime.now() - datetime.timedelta(days=days_ago)
            ).replace(microsecond=0).isoformat(sep=" ")


class Base(unittest.TestCase):
    def setUp(self):
        fd, self.db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.pool = pool_mod.Pool(self.db, server="test")
        self.uid = self.pool.upsert_proxy({
            "provider": "proxy6", "ext_id": "1", "ip": "1.1.1.1", "host": "1.1.1.1",
            "port_http": 8080, "port_socks5": 1080, "user": "u", "password": "p",
            "country": "ng", "ip_version": 4, "kind": "dedicated",
            "date_end": None, "descr": ""})

    def tearDown(self):
        self.pool.close()
        os.unlink(self.db)

    def log_rows(self):
        return [dict(r) for r in self.pool.conn.execute(
            "SELECT * FROM probe_log ORDER BY id").fetchall()]


class TestProbeLogWrites(Base):
    def test_success_written_with_passport_and_fact(self):
        self.pool.record_probe(self.uid, {"ok": True, "socks_ok": True, "http_ok": True,
                                          "tg_ok": True, "exit_ip": "5.5.5.5",
                                          "exit_cc": "us", "geo_agree": False,
                                          "latency_ms": 120, "score": 100.0},
                               is_current=True, strategy="reputation")
        rows = self.log_rows()
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual(r["uid"], self.uid)
        self.assertEqual(r["provider"], "proxy6")
        self.assertEqual(r["exit_cc"], "us", "фактическая страна — как увидела проба")
        self.assertEqual(r["country"], "ng", "паспортная — как продана; без подмен")
        self.assertEqual(r["geo_agree"], 0)
        self.assertEqual(r["ok"], 1)
        self.assertEqual(r["is_current"], 1)
        self.assertEqual(r["strategy"], "reputation")

    def test_history_survives_overwrite(self):
        # строка proxy перетирается, а история накапливается; fail_count в строке
        # обнулился успехом, но провалы остались видны в журнале
        self.pool.record_probe(self.uid, {"ok": False, "disqualified": "no-combo"})
        self.pool.record_probe(self.uid, {"ok": False, "disqualified": "no-combo"})
        self.pool.record_probe(self.uid, {"ok": True, "socks_ok": True, "http_ok": True,
                                          "tg_ok": True, "exit_cc": "ng",
                                          "latency_ms": 90, "score": 120.0})
        rows = self.log_rows()
        self.assertEqual([r["ok"] for r in rows], [0, 0, 1])
        self.assertEqual(rows[0]["disq"], "no-combo")
        self.assertEqual(self.pool.get(self.uid)["fail_count"], 0)

    def test_unknown_uid_not_logged(self):
        self.pool.record_probe("proxy6:нет", {"ok": True})
        self.assertEqual(self.log_rows(), [])


class TestPrune(Base):
    def seed_history(self):
        c = self.pool.conn
        for days_ago, ok in ((120, 1), (91, 0), (89, 1), (1, 1)):
            c.execute("INSERT INTO probe_log(ts, uid, provider, ok, strategy)"
                      " VALUES(?,?,?,?,'')", (_iso(days_ago), self.uid, "proxy6", ok))
        for days_ago in (200, 181, 179, 2):
            c.execute("INSERT INTO event(ts, action, result) VALUES(?, 'x', 'ok')",
                      (_iso(days_ago),))
        c.execute("INSERT INTO money(ts, provider, op, uid, price, currency)"
                  " VALUES(?, 'proxy6', 'buy', ?, 28.0, 'RUB')", (_iso(400), self.uid))
        c.commit()

    def test_prune_cuts_by_age_money_forever(self):
        self.seed_history()
        r = self.pool.prune()
        self.assertEqual(r["probe_log"], 2, "старше 90 дней — под нож")
        self.assertGreaterEqual(r["event"], 2, "event старше 180 дней — под нож")
        left = self.pool.conn.execute("SELECT COUNT(*) FROM probe_log").fetchone()[0]
        self.assertEqual(left, 2)
        money_left = self.pool.conn.execute("SELECT COUNT(*) FROM money").fetchone()[0]
        self.assertEqual(money_left, 1, "финансовая история вечная")

    def test_prune_once_a_day(self):
        self.seed_history()
        self.assertIsNotNone(self.pool.prune())
        self.assertIsNone(self.pool.prune(), "второй раз в те же сутки — no-op")
        tomorrow = datetime.datetime.now() + datetime.timedelta(days=1)
        self.assertIsNotNone(self.pool.prune(now=tomorrow), "на следующий день — снова можно")


class TestProbeStrategyIndependence(unittest.TestCase):
    """E3: у пробы нет ручки «стратегия» — результат один при любой настройке."""

    def test_probe_signature_has_no_strategy_knob(self):
        params = set(inspect.signature(probe.probe).parameters)
        self.assertEqual(params, {"proxy", "provider_check", "latency_runs"},
                         "у probe.probe не должно появиться параметра стратегии/cfg")

    def test_probe_result_identical_with_mocked_network(self):
        # сеть замокана: гоняем пробу дважды, между прогонами «меняем стратегию»
        # (конфиг, который probe в принципе не видит) — результаты идентичны
        orig_run, orig_geo = probe._run_curl, probe.geo_country_consensus
        try:
            probe._run_curl = lambda args, timeout=probe.CURL_TIMEOUT: (
                (0, "5.5.5.5") if probe.IPIFY_URL in args
                else (0, "204") if "%{http_code}" in args
                else (0, "0.1"))
            probe.geo_country_consensus = lambda ip: {"cc": "fi", "alt": "fi", "agree": True}
            px = {"host": "1.1.1.1", "port_socks5": 1080, "port_http": 8080,
                  "user": "u", "password": "p"}
            fake_cfg = {"countries": {"strategy": "reputation"}}
            res1 = probe.probe(dict(px))
            fake_cfg["countries"]["strategy"] = "speed"     # noqa: F841 — probe его не видит
            res2 = probe.probe(dict(px))
            self.assertEqual(res1, res2)
            self.assertTrue(res1["ok"])
        finally:
            probe._run_curl, probe.geo_country_consensus = orig_run, orig_geo


class TestStrategyPreviewNoNetwork(unittest.TestCase):
    """E3: превью стратегий (карточка) считается в памяти, без сетевых вызовов."""

    def test_strategy_state_makes_no_network_calls(self):
        import json as _json
        import sys
        import urllib.request
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "webpanel"))
        import server
        import subprocess

        tmp = tempfile.TemporaryDirectory()
        d = tmp.name
        with open(os.path.join(d, "secrets.json"), "w", encoding="utf-8") as f:
            _json.dump({"admin": {"pw": "x", "totp": "S"},
                        "proxy6": {"api_key": "aaaa0bcde1-22222fghi3-4444jklm55"}}, f)
        with open(os.path.join(d, "config.json"), "w", encoding="utf-8") as f:
            _json.dump({"server": "t", "role": "t", "db": os.path.join(d, "state.db"),
                        "ring": os.path.join(d, "cfg"), "server_ip": "127.0.0.1"}, f)
        env_saved = (os.environ.get("VPN_PANEL_CONFIG"), os.environ.get("VPN_PANEL_SECRETS"))
        os.environ["VPN_PANEL_CONFIG"] = os.path.join(d, "config.json")
        os.environ["VPN_PANEL_SECRETS"] = os.path.join(d, "secrets.json")
        app = server.App()
        app_saved, server.APP = server.APP, app
        app.pool.upsert_proxy({"provider": "proxy6", "ext_id": "1", "ip": "1.1.1.1",
                               "host": "1.1.1.1", "port_http": 8080, "port_socks5": 1080,
                               "user": "u", "password": "p", "country": "fi",
                               "ip_version": 4, "kind": "dedicated",
                               "date_end": None, "descr": ""})

        def boom(*a, **kw):
            raise AssertionError("превью стратегий не должно ходить в сеть/подпроцессы")

        saved = (urllib.request.urlopen, subprocess.run)
        urllib.request.urlopen = boom
        subprocess.run = boom

        class H:
            _strategy_state = server.Handler._strategy_state
            _brief = staticmethod(server.Handler._brief)

        try:
            st = H()._strategy_state()
            self.assertEqual(len(st["strategies"]), 4)
            self.assertEqual(st["pool_size"], 1)
        finally:
            urllib.request.urlopen, subprocess.run = saved
            server.APP = app_saved
            app.pool.close()
            for name, val in zip(("VPN_PANEL_CONFIG", "VPN_PANEL_SECRETS"), env_saved):
                if val is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = val
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main(verbosity=2)
