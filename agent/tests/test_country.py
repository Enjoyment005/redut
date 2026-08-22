# -*- coding: utf-8 -*-
"""Политика стран (§6.1, решение владельца 2026-08-15): чёрный список — навсегда,
остальные страны не запрещены, а получают умную оценку.

Отдельный файл, потому что от этих правил зависят реальные траты денег и выбор
боевого выхода: их лучше ломать тестом, а не в бою.
"""
import unittest

import _ctx      # noqa: F401  (добавляет panel/ в sys.path)
import country
import probe
from providers import base

REP = {"countries": {"strategy": "reputation"}}


class TestBlacklist(unittest.TestCase):
    def test_exactly_three(self):
        self.assertEqual(set(country.BLACKLIST_CC), {"ru", "ua", "by"})

    def test_all_copies_agree(self):
        """Три независимых предохранителя на разных слоях не должны разойтись."""
        self.assertEqual(set(country.BLACKLIST_CC), set(probe.HARD_BLOCK_CC))
        self.assertEqual(set(country.BLACKLIST_CC), set(base.HARD_BLOCK_CC))

    def test_blocked_rating_is_none(self):
        for cc in ("ru", "ua", "by", "RU", " By "):
            self.assertTrue(country.is_blocked(cc))
            self.assertIsNone(country.rating(cc))
            self.assertEqual(country.tier(cc), "blocked")

    def test_config_can_only_extend(self):
        cfg = {"countries": {"blacklist": ["ng"]}}
        self.assertTrue(country.is_blocked("ng", cfg))
        self.assertTrue(country.is_blocked("ru", cfg))
        # попытка «сузить» игнорируется: список из кода всё равно в силе
        self.assertTrue(country.is_blocked("ru", {"countries": {"blacklist": []}}))


class TestRating(unittest.TestCase):
    def test_order_of_tiers(self):
        self.assertGreater(country.rating("de", cfg=REP), country.rating("jp", cfg=REP))
        self.assertGreater(country.rating("jp", cfg=REP), country.rating("zz", cfg=REP))
        self.assertGreater(country.rating("zz", cfg=REP), country.rating("ng", cfg=REP))

    def test_unknown_country_is_neutral_not_punished(self):
        self.assertEqual(country.rating(None, cfg=REP), country.RATING_NEUTRAL)
        self.assertEqual(country.rating("zz", cfg=REP), country.RATING_NEUTRAL)

    def test_geo_mismatch_penalty(self):
        """Случай 203.0.113.77: ip-api видит Нигерию, ipinfo — США."""
        self.assertEqual(country.rating("de", geo_agree=False, cfg=REP),
                         country.rating("de", cfg=REP) + country.GEO_MISMATCH_PENALTY)
        self.assertEqual(country.tier("de", geo_agree=False), "disputed")

    def test_auto_allowed(self):
        for cc in ("fi", "lv", "de", "us", "jp"):
            self.assertTrue(country.auto_allowed(cc, cfg=REP), cc)
        for cc in ("ng", "kz", "br", "tr", "ru"):
            self.assertFalse(country.auto_allowed(cc, cfg=REP), cc)

    def test_trusted_with_disputed_geo_drops_below_auto_threshold(self):
        # надёжная страна, но базы разошлись: 25 - 20 = 5, всё ещё можно авто
        self.assertTrue(country.auto_allowed("de", geo_agree=False, cfg=REP))
        # нейтральная + расхождение уходит в минус — авто уже нельзя
        self.assertFalse(country.auto_allowed("zz", geo_agree=False, cfg=REP))

    def test_explain_is_human_readable(self):
        self.assertIn("чёрном списке", country.explain("ru"))
        self.assertIn("расходятся", country.explain("de", geo_agree=False))
        self.assertIn("надёжная", country.explain("fi"))
        self.assertIn("высоким риском", country.explain("ng"))


class TestRank(unittest.TestCase):
    def test_drops_blocked_and_sorts(self):
        self.assertEqual(country.rank(["ng", "ru", "de", "jp"], REP), ["de", "jp", "ng"])

    def test_stable_within_same_rating(self):
        # у fi и de одинаковый рейтинг -> сохраняется входной порядок (задержка из РФ)
        self.assertEqual(country.rank(["fi", "de"], REP), ["fi", "de"])
        self.assertEqual(country.rank(["de", "fi"], REP), ["de", "fi"])


class TestProbeIntegration(unittest.TestCase):
    def test_score_prefers_trusted_country(self):
        row = {"fail_count": 0, "kind": "dedicated", "ip_version": 4, "date_end": None}
        res = {"ok": True, "latency_ms": 100, "tg_ok": True, "socks_ok": True,
               "http_ok": True, "geo_agree": True}
        lv = probe.score(row, dict(res, exit_cc="lv"), cfg=REP)
        ng = probe.score(row, dict(res, exit_cc="ng"), cfg=REP)
        self.assertGreater(lv, ng, "Латвия должна обгонять Нигерию при равном качестве")
        self.assertEqual(round(lv - ng, 1),
                         float(country.RATING_TRUSTED - country.RATING_LOW))

    def test_score_punishes_geo_mismatch(self):
        row = {"fail_count": 0, "kind": "dedicated", "ip_version": 4, "date_end": None}
        base_res = {"ok": True, "latency_ms": 100, "tg_ok": True, "socks_ok": True,
                    "http_ok": True, "exit_cc": "de"}
        agree = probe.score(row, dict(base_res, geo_agree=True), cfg=REP)
        disput = probe.score(row, dict(base_res, geo_agree=False), cfg=REP)
        self.assertEqual(round(agree - disput, 1), float(-country.GEO_MISMATCH_PENALTY))

    def test_consensus_no_data_is_not_a_mismatch(self):
        """Обе базы промолчали — это незнание, а не расхождение: штрафа нет."""
        self.assertEqual(probe.geo_country_consensus(None),
                         {"cc": None, "alt": None, "agree": True})


if __name__ == "__main__":
    unittest.main(verbosity=2)
