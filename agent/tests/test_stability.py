# -*- coding: utf-8 -*-
"""Пакет F8 (П6): обучение стабильности — история -> решения о покупке.

Ключ агрегата — ПАСПОРТНАЯ страна покупки (bonus применяется к стране, которую
покупаем); порог обучения по объёму данных; бонус не пробивает чёрный список
и auto-гейты; в оценку живых проб бонус не идёт.
"""
import datetime
import os
import tempfile
import unittest

import _ctx      # noqa: F401
import money
import pool as pool_mod


def _iso_days_ago(days):
    return (datetime.datetime.now() - datetime.timedelta(days=days)
            ).replace(microsecond=0).isoformat(sep=" ")


def agg(ok=300, fail=0, drops=0, seconds=0, days=30, provider="proxy6", country="fi"):
    return {"provider": provider, "country": country, "probes_ok": ok, "probes_fail": fail,
            "battle_drops": drops, "battle_seconds": seconds,
            "first_seen": _iso_days_ago(days), "last_seen": _iso_days_ago(0)}


class TestBonusFormula(unittest.TestCase):
    def test_below_probe_threshold_is_zero(self):
        self.assertEqual(money.stability_bonus(agg(ok=299, fail=0, days=60)), 0.0)

    def test_below_day_threshold_is_zero(self):
        self.assertEqual(money.stability_bonus(agg(ok=1000, days=20)), 0.0)

    def test_none_is_zero(self):
        self.assertEqual(money.stability_bonus(None), 0.0)

    def test_at_threshold_jump_is_small(self):
        # maturity на пороге ≈ 0.3*0.35 = 0.105 -> бонус ≤ ~2 балла (принято ревью)
        b = money.stability_bonus(agg(ok=300, fail=0, days=21))
        self.assertGreater(b, 0.0)
        self.assertLessEqual(b, 2.5)

    def test_beta_smoothing_keeps_5050_neutral(self):
        self.assertEqual(money.stability_bonus(agg(ok=500, fail=500, days=60)), 0.0)

    def test_mature_reliable_pair_positive(self):
        b = money.stability_bonus(agg(ok=1000, fail=10, days=60))
        self.assertGreater(b, 15.0)

    def test_mature_unreliable_pair_negative(self):
        # (300+5)/1010 ≈ 0.302 -> 40*(0.302-0.5) ≈ −7.9
        b = money.stability_bonus(agg(ok=300, fail=700, days=60))
        self.assertLess(b, -5.0)

    def test_drop_rate_penalty_capped(self):
        clean = money.stability_bonus(agg(ok=1000, days=60, seconds=3600 * 100))
        # 1000 обрывов за 100 часов боя: rate=10 -> min(rate,2)=2 -> −10 от чистого
        dropped = money.stability_bonus(agg(ok=1000, days=60, seconds=3600 * 100, drops=1000))
        self.assertAlmostEqual(clean - dropped, 10.0, places=1)

    def test_clamped_to_cap(self):
        b = money.stability_bonus(agg(ok=100000, fail=0, days=600))
        self.assertLessEqual(abs(b), 20.0)

    def test_config_overrides_thresholds(self):
        cfg = {"stability": {"min_probes": 10, "min_days": 1}}
        self.assertNotEqual(money.stability_bonus(agg(ok=50, fail=0, days=2), cfg), 0.0)
        self.assertEqual(money.stability_bonus(agg(ok=50, fail=0, days=2)), 0.0,
                         "без конфига дефолтный порог строже")


class TestAggregation(unittest.TestCase):
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

    def test_probe_counts_by_passport_country(self):
        # кейс из плана: продан как ng, выходит в us -> ключ агрегата ng (паспорт),
        # фактическая страна остаётся диагностикой в probe_log
        self.pool.record_probe(self.uid, {"ok": True, "socks_ok": True, "exit_cc": "us"})
        self.pool.record_probe(self.uid, {"ok": False})
        self.assertIsNone(self.pool.stability_get("proxy6", "us"))
        s = self.pool.stability_get("proxy6", "ng")
        self.assertEqual((s["probes_ok"], s["probes_fail"]), (1, 1))

    def test_drop_and_battle_accumulate(self):
        self.pool.stability_bump_drop("proxy6", "ng")
        self.pool.stability_bump_battle("proxy6", "ng", 300)
        self.pool.stability_bump_battle("proxy6", "ng", 600)
        s = self.pool.stability_get("proxy6", "ng")
        self.assertEqual(s["battle_drops"], 1)
        self.assertEqual(s["battle_seconds"], 900)

    def test_no_country_no_row(self):
        self.pool.stability_bump_probe("proxy6", None, True)
        self.pool.stability_bump_probe("proxy6", "", False)
        self.assertEqual(self.pool.stability_all(), [])

    def test_first_seen_stable_last_seen_moves(self):
        self.pool.stability_bump_probe("proxy6", "ng", True)
        first = self.pool.stability_get("proxy6", "ng")["first_seen"]
        self.pool.stability_bump_probe("proxy6", "ng", True)
        s = self.pool.stability_get("proxy6", "ng")
        self.assertEqual(s["first_seen"], first, "first_seen не перетирается")

    def test_pruning_leaves_stability(self):
        self.pool.stability_bump_probe("proxy6", "ng", True)
        self.pool.prune()
        self.assertIsNotNone(self.pool.stability_get("proxy6", "ng"),
                             "retention агрегат не трогает")


class TestBuyRanking(unittest.TestCase):
    """Применение — ровно одна точка: money.buy_candidates."""

    def setUp(self):
        fd, self.db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.pool = pool_mod.Pool(self.db, server="test")

    def tearDown(self):
        self.pool.close()
        os.unlink(self.db)

    def seed(self, country, ok=1000, fail=0, days=60, drops=0, seconds=0):
        now = _iso_days_ago(0)
        self.pool.conn.execute(
            "INSERT INTO stability(provider, country, probes_ok, probes_fail, battle_drops,"
            " battle_seconds, first_seen, last_seen) VALUES('proxy6',?,?,?,?,?,?,?)",
            (country, ok, fail, drops, seconds, _iso_days_ago(days), now))
        self.pool.conn.commit()

    def cfg(self, strategy="reputation", whitelist=("fi", "de")):
        return {"countries": {"whitelist": list(whitelist), "strategy": strategy}}

    def test_bonus_reorders_equal_countries(self):
        # fi и de обе trusted (+25); выученная надёжность de поднимает её на верх
        # внутреннего порядка, а провальная история fi роняет её ниже прочих trusted
        self.seed("de", ok=1000, fail=0, days=60)
        self.seed("fi", ok=300, fail=700, days=60)
        out = money.buy_candidates(self.cfg(), pool=self.pool)
        self.assertEqual(out[0], "de")
        self.assertLess(out.index("de"), out.index("fi"))

    def test_without_pool_order_unchanged(self):
        # без пула порядок задаёт внутренний рейтинг + близость (fi раньше de)
        out = money.buy_candidates(self.cfg())
        self.assertLess(out.index("fi"), out.index("de"))
        self.assertEqual(out[0], "fi")

    def test_learning_pair_does_not_move(self):
        self.seed("de", ok=50, fail=0, days=3)      # мало данных — бонус 0
        out = money.buy_candidates(self.cfg(), pool=self.pool)
        self.assertLess(out.index("fi"), out.index("de"))

    def test_bonus_cannot_beat_blacklist(self):
        self.seed("ru", ok=100000, fail=0, days=600)
        out = money.buy_candidates(self.cfg(whitelist=("fi", "ru")), pool=self.pool)
        self.assertNotIn("ru", out, "чёрный список отсекается ДО бонуса")

    def test_bonus_cannot_open_auto_gate(self):
        # ng — рискованная: auto_allowed=false при reputation; идеальная история не пускает
        self.seed("ng", ok=100000, fail=0, days=600)
        out = money.buy_candidates(self.cfg(), available=["ng"], pool=self.pool)
        self.assertNotIn("ng", out, "auto_allowed бонусом не обходится")

    def test_probe_score_untouched_by_stability(self):
        # в оценку живых проб бонус не идёт: живой замер лучше любой истории
        import probe
        self.seed("fi", ok=100000, fail=0, days=600)
        row = {"kind": "dedicated", "ip_version": 4, "fail_count": 0,
               "date_end": None, "country": "fi"}
        res = {"ok": True, "latency_ms": 100, "tg_ok": True, "socks_ok": True,
               "http_ok": True, "exit_cc": "fi", "geo_agree": True}
        self.assertEqual(probe.score(row, res, cfg=self.cfg()),
                         probe.score(row, res, cfg=self.cfg()))
        # формула не имеет доступа к pool вовсе — фиксируем сигнатурой
        import inspect
        self.assertNotIn("pool", inspect.signature(probe.score).parameters)
        self.assertNotIn("pool", inspect.signature(probe.score_from_row).parameters)


if __name__ == "__main__":
    unittest.main(verbosity=2)
