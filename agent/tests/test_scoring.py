# -*- coding: utf-8 -*-
"""Скоринг §7.4 и days_left."""
import unittest
import datetime

import _ctx
import probe


def res(ok=True, latency=100, tg=True, socks=True, http=True):
    return {"ok": ok, "latency_ms": latency, "tg_ok": tg, "socks_ok": socks, "http_ok": http}


def row(kind="dedicated", ipv=4, fails=0, date_end=None):
    return {"kind": kind, "ip_version": ipv, "fail_count": fails, "date_end": date_end}


class TestScore(unittest.TestCase):
    def test_baseline(self):
        # 100 − 10 (latency 100ms) + 20 (tg) + 15 (оба протокола) + 10 (dedicated v4)
        self.assertEqual(probe.score(row(), res()), 135.0)

    def test_latency_capped_at_40(self):
        self.assertEqual(probe.score(row(), res(latency=9000)),
                         probe.score(row(), res(latency=400)),
                         "штраф за латентность ограничен 40")

    def test_fail_count_penalty(self):
        base = probe.score(row(), res())
        self.assertEqual(probe.score(row(fails=2), res()), base - 30)

    def test_tg_bonus(self):
        self.assertEqual(probe.score(row(), res()) - probe.score(row(), res(tg=False)), 20)

    def test_both_protocols_bonus(self):
        self.assertEqual(probe.score(row(), res()) - probe.score(row(), res(http=False)), 15)

    def test_shared_penalty(self):
        self.assertEqual(probe.score(row(), res()) - probe.score(row(kind="shared"), res()), 30,
                         "+10 dedicated против −20 shared")

    def test_ipv6_no_dedicated_bonus(self):
        self.assertEqual(probe.score(row(), res()) - probe.score(row(ipv=6), res()), 10)

    def test_current_stickiness(self):
        self.assertEqual(probe.score(row(), res(), is_current=True) - probe.score(row(), res()), 15)

    def test_expiring_penalty(self):
        soon = (datetime.datetime.now() + datetime.timedelta(days=1)).isoformat(sep=" ")
        later = (datetime.datetime.now() + datetime.timedelta(days=30)).isoformat(sep=" ")
        self.assertEqual(probe.score(row(date_end=later), res())
                         - probe.score(row(date_end=soon), res()), 30,
                         "−30 если до date_end < 2 суток")

    def test_disqualified_is_none(self):
        self.assertIsNone(probe.score(row(), res(ok=False)),
                          "не работает ни одна комбинация — дисквалификация")

    def test_days_left_formats(self):
        self.assertIsNone(probe.days_left(""))
        self.assertIsNone(probe.days_left("мусор"))
        # формат PROXY6 'YYYY-MM-DD HH:MM:SS' и ISO ProxyLine с таймзоной
        self.assertIsNotNone(probe.days_left("2026-09-01 10:00:00"))
        self.assertIsNotNone(probe.days_left("2022-09-15T14:48:15.355913+03:00"))


class TestHardBlock(unittest.TestCase):
    def test_constant(self):
        # §6.1 (с 2026-08-15): в чёрном списке ровно три страны
        for cc in ("ru", "ua", "by"):
            self.assertIn(cc, probe.HARD_BLOCK_CC)
        for cc in ("fi", "de", "nl", "us"):
            self.assertNotIn(cc, probe.HARD_BLOCK_CC)

    def test_ex_cis_not_blocked_but_low_rated(self):
        """Бывшие в блоке страны СНГ теперь разрешены, но с низкой оценкой —
        автоматика их сама не покупает, человек может."""
        import country
        cfg = {"countries": {"strategy": "reputation"}}
        for cc in ("kz", "kg", "tj", "uz", "tm", "am", "az", "md", "ge"):
            self.assertNotIn(cc, probe.HARD_BLOCK_CC)
            self.assertIsNotNone(country.rating(cc, cfg=cfg))
            self.assertFalse(country.auto_allowed(cc, cfg=cfg))


if __name__ == "__main__":
    unittest.main(verbosity=2)
