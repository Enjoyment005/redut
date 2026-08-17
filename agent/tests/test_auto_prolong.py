# -*- coding: utf-8 -*-
"""Автопродление «якоря» (§6.3, решение владельца 15.08).

Здесь списываются реальные деньги, поэтому тестами закрыты именно опасные места:
кого трогаем (только боевой), когда (порог дней), и что НЕ продлеваем дважды.
"""
import datetime
import os
import tempfile
import unittest

import _ctx      # noqa: F401
import pool as pool_mod
import states as states_mod


def _in(days):
    return (datetime.datetime.now() + datetime.timedelta(days=days)).replace(
        microsecond=0).isoformat(sep=" ")


class FakeProv:
    caps = {"prolong": True, "buy": True, "delete": True}
    name = "proxy6"        # C5: money сверяет адаптер с провайдером строки

    def __init__(self, name=None):
        if name:
            self.name = name
        self.calls = []

    def getprice(self, count, days, version):
        return {"price": 4.0 * days, "balance": 800.0, "currency": "RUB"}

    def prolong(self, ext_id, days):
        self.calls.append((ext_id, days))
        return {"price": 4.0 * days, "balance": 800.0 - 4.0 * days, "currency": "RUB",
                "proxies": {str(ext_id): {"date_end": _in(days)}}, "order_id": "o1"}


class FakeAlerter:
    def __init__(self):
        self.sent = []

    def prolonged(self, **kw):
        self.sent.append(("prolonged", kw))

    def prolong_failed(self, **kw):
        self.sent.append(("failed", kw))


class Base(unittest.TestCase):
    def setUp(self):
        fd, self.db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.pool = pool_mod.Pool(self.db, server="node1")
        self.prov = FakeProv()
        self.alerter = FakeAlerter()
        self.cfg = {"server": "node1", "singbox_config": "cfg.json", "role": "vpn-node1",
                    "money": {"buy_enabled": True, "max_buys_per_day": 3, "max_spend_per_day": 300,
                              "max_price_per_buy": 150, "min_balance_reserve": 300,
                              "buy_period_days": 7, "buy_version": 4, "currency": "RUB"},
                    "auto_prolong": {"enabled": True, "days_before": 3, "period_days": 30,
                                     "scope": "current"}}
        # два прокси: боевой (хост совпадёт с current_upstream) и запасной
        for uid, host, role, days, ok in [("proxy6:1", "1.1.1.1", "auto", 2, 1),
                                          ("proxy6:2", "2.2.2.2", "reserve", 2, 1)]:
            self.pool.conn.execute(
                "INSERT INTO proxy(uid,provider,ext_id,host,role,gone,date_end,probe_ok,country)"
                " VALUES(?,?,?,?,?,0,?,?,?)",
                (uid, "proxy6", uid.split(":")[1], host, role, _in(days), ok, "lv"))
        self.pool.conn.commit()
        # current_upstream читает конфиг sing-box — подменяем на «боевой = 1.1.1.1»
        self._orig = states_mod.apply_mod.current_upstream, states_mod.apply_mod.load_json
        states_mod.apply_mod.load_json = lambda p: {}
        states_mod.apply_mod.current_upstream = lambda sb: "1.1.1.1"

    def tearDown(self):
        states_mod.apply_mod.current_upstream, states_mod.apply_mod.load_json = (
            self._orig[0], self._orig[1])
        self.pool.close()
        os.unlink(self.db)

    def run_it(self):
        return states_mod.auto_prolong(self.cfg, {"proxy6": self.prov}, self.pool,
                                       self.alerter, log=lambda *a: None)


class TestScope(Base):
    def test_prolongs_only_current(self):
        r = self.run_it()
        self.assertEqual([c[0] for c in self.prov.calls], ["1"], "трогаем только боевой")
        self.assertEqual(r["prolonged"][0]["uid"], "proxy6:1")
        self.assertEqual(self.prov.calls[0][1], 30, "период из конфига")

    def test_dead_scope_ignored(self):
        # B6 (роли v2): scope "current+reserve" опирался на роль reserve и выпилен.
        # Старое значение в конфиге не должно ни падать, ни продлевать лишнее.
        self.cfg["auto_prolong"]["scope"] = "current+reserve"
        self.run_it()
        self.assertEqual([c[0] for c in self.prov.calls], ["1"], "только боевой, резерва больше нет")

    def test_disabled_toggle(self):
        self.cfg["auto_prolong"]["enabled"] = False
        r = self.run_it()
        self.assertEqual(self.prov.calls, [])
        self.assertIn("выключено", r["skipped"])


class TestProviderMatch(Base):
    """C5: адаптер строго по провайдеру строки — чужой ext_id не трогаем."""

    def make_battle_proxyline(self):
        """Боевой канал — от ProxyLine (host совпадает с current_upstream)."""
        self.pool.conn.execute(
            "INSERT INTO proxy(uid,provider,ext_id,host,role,gone,date_end,probe_ok,country)"
            " VALUES('proxyline:7','proxyline','7','3.3.3.3','auto',0,?,1,'de')", (_in(2),))
        self.pool.conn.commit()
        states_mod.apply_mod.current_upstream = lambda sb: "3.3.3.3"

    def test_no_adapter_for_battle_alerts_not_silent(self):
        # боевой от proxyline, ключ есть только у proxy6: НЕ зовём proxy6.prolong
        # с чужим ext_id=7 — событие + алерт вместо молчаливого skip
        self.make_battle_proxyline()
        r = states_mod.auto_prolong(self.cfg, {"proxy6": self.prov}, self.pool,
                                    self.alerter, log=lambda *a: None)
        self.assertEqual(self.prov.calls, [], "prolong с чужим ext_id не ушёл")
        self.assertEqual(r["prolonged"], [])
        self.assertEqual(self.alerter.sent[0][0], "failed")
        ev = self.pool.conn.execute(
            "SELECT result FROM event WHERE action='auto-prolong'").fetchone()
        self.assertEqual(ev["result"], "no-provider")

    def test_right_adapter_chosen_by_row_provider(self):
        self.make_battle_proxyline()
        pl = FakeProv(name="proxyline")
        states_mod.auto_prolong(self.cfg, {"proxy6": self.prov, "proxyline": pl},
                                self.pool, self.alerter, log=lambda *a: None)
        self.assertEqual(self.prov.calls, [], "proxy6 не трогали")
        self.assertEqual([c[0] for c in pl.calls], ["7"], "продлил адаптер ProxyLine")

    def test_gone_battle_row_still_alerts(self):
        # ревью 1.3.0: после удаления ключа строки провайдера gone, но боевой канал
        # в sing-box живёт — алерт «продлить нечем» обязан уйти, а не молчаливый skip
        self.make_battle_proxyline()
        self.pool.conn.execute("UPDATE proxy SET gone=1 WHERE uid='proxyline:7'")
        self.pool.conn.commit()
        r = states_mod.auto_prolong(self.cfg, {"proxy6": self.prov}, self.pool,
                                    self.alerter, log=lambda *a: None)
        self.assertNotIn("skipped", r, "боевой найден даже gone-строкой")
        self.assertEqual(self.alerter.sent[0][0], "failed")


class TestTiming(Base):
    def test_too_early_not_touched(self):
        """До истечения далеко — деньги не морозим заранее."""
        self.pool.conn.execute("UPDATE proxy SET date_end=? WHERE uid='proxy6:1'", (_in(10),))
        self.pool.conn.commit()
        r = self.run_it()
        self.assertEqual(self.prov.calls, [])
        self.assertEqual(r["prolonged"], [])

    def test_no_date_end_not_touched(self):
        self.pool.conn.execute("UPDATE proxy SET date_end=NULL WHERE uid='proxy6:1'")
        self.pool.conn.commit()
        self.run_it()
        self.assertEqual(self.prov.calls, [])

    def test_sick_proxy_not_prolonged(self):
        """Мёртвый якорь продлевать бессмысленно — его заменит ротация."""
        self.pool.conn.execute("UPDATE proxy SET probe_ok=0 WHERE uid='proxy6:1'")
        self.pool.conn.commit()
        self.run_it()
        self.assertEqual(self.prov.calls, [])


class TestIdempotency(Base):
    def test_not_twice_a_day(self):
        self.run_it()
        self.run_it()      # второй запуск крона в те же сутки
        self.assertEqual(len(self.prov.calls), 1, "повторного списания быть не должно")

    def test_prolonged_today_flag(self):
        self.assertFalse(self.pool.prolonged_today("proxy6:1"))
        self.run_it()
        self.assertTrue(self.pool.prolonged_today("proxy6:1"))
        self.assertFalse(self.pool.prolonged_today("proxy6:2"))


class TestGatesAndAlerts(Base):
    def test_denied_by_limit_alerts_owner(self):
        """Гейт не пустил — молчать нельзя: иначе якорь тихо истечёт."""
        self.cfg["money"]["max_price_per_buy"] = 10    # 30 дн = 120 ₽ > 10
        r = self.run_it()
        self.assertEqual(self.prov.calls, [])
        self.assertEqual(r["prolonged"], [])
        self.assertEqual(self.alerter.sent[0][0], "failed")
        self.assertIn("proxy6:1", self.alerter.sent[0][1]["uid"])

    def test_success_alerts_and_records_money(self):
        self.run_it()
        self.assertEqual(self.alerter.sent[0][0], "prolonged")
        rows = self.pool.conn.execute("SELECT op,uid,price FROM money").fetchall()
        self.assertEqual([(r["op"], r["uid"], r["price"]) for r in rows],
                         [("prolong", "proxy6:1", 120.0)])

    def test_toggle_off_blocks_spending(self):
        self.cfg["money"]["buy_enabled"] = False
        self.run_it()
        self.assertEqual(self.prov.calls, [])
        self.assertEqual(self.alerter.sent[0][0], "failed")


if __name__ == "__main__":
    unittest.main(verbosity=2)
