# -*- coding: utf-8 -*-
"""Стратегии выбора стран (§6.1, настройка админа 2026-08-17).

Стратегия меняет три вещи — где автоматике можно покупать, в каком порядке перебирать
пул и сколько весит страна в оценке пробы. Это прямо про деньги и про то, из какой
страны увидят клиента, поэтому проверяем каждое из трёх для каждой стратегии, а
отдельно — что **ни одна** не открывает чёрный список и что эксплуатационный
дефолт — «Скорость и отклик».
"""
import unittest

import _ctx      # noqa: F401  (добавляет panel/ в sys.path)
import country
import money
import probe
import states

WL = ["fi", "ee", "lv", "de"]


def cfg(strategy=None, whitelist=None, blacklist=None):
    c = {"countries": {"whitelist": list(WL if whitelist is None else whitelist),
                       "blacklist": list(blacklist or [])}}
    if strategy:
        c["countries"]["strategy"] = strategy
    return c


def row(host, cc, probe_ok=0, score=None, **meas):
    """Строка пула. Оценка с 1.3.0 (П3) считается на лету из ЗАМЕРОВ строки
    (latency_ms/tg_ok/http_ok/kind — kwargs); колонка score потребителями не
    читается и оставлена в фикстуре только как «последний замер»."""
    r = {"uid": "proxy6:%s" % host, "host": host, "country": cc, "exit_cc": cc,
         "probe_ok": probe_ok, "score": score, "role": "auto",
         "latency_ms": None, "tg_ok": 0, "socks_ok": probe_ok, "http_ok": 0,
         "kind": None, "ip_version": 4, "fail_count": 0, "date_end": None,
         "geo_agree": 1}
    r.update(meas)
    return r


class TestSelection(unittest.TestCase):
    def test_three_strategies_and_default(self):
        # стратегии «только избранные» больше нет (приёмка №7): белый список умер
        self.assertEqual(list(country.STRATEGIES), ["reputation", "balanced", "speed"])
        self.assertEqual(country.DEFAULT_STRATEGY, "speed")

    def test_unknown_or_missing_falls_back_to_default(self):
        # сюда же падают узлы со старой стратегией "whitelist" из конфига
        for c in (None, {}, cfg(), cfg("нет-такой"), cfg("whitelist"),
                  {"countries": {"strategy": ""}}):
            self.assertEqual(country.strategy(c), "speed")

    def test_strategy_is_case_and_space_tolerant(self):
        self.assertEqual(country.strategy({"countries": {"strategy": " SPEED "}}), "speed")

    def test_info_carries_id_and_human_text(self):
        info = country.strategy_info(cfg("speed"))
        self.assertEqual(info["id"], "speed")
        for field in ("title", "short", "desc"):
            self.assertTrue(len(info[field]) > 10, field)


class TestBlacklistHoldsEverywhere(unittest.TestCase):
    """Ни одна стратегия не должна открывать ru/ua/by — это запрет в коде."""

    def test_rating_none_and_auto_denied(self):
        for sid in country.STRATEGIES:
            for cc in ("ru", "ua", "by"):
                self.assertIsNone(country.rating(cc, True, cfg(sid)), (sid, cc))
                self.assertFalse(country.auto_allowed(cc, True, cfg(sid)), (sid, cc))
                self.assertEqual(country.tier(cc, True, cfg(sid)), "blocked")

    def test_candidates_dropped_in_every_strategy(self):
        rows = [row("r", "ru", 1, 200.0), row("d", "de")]
        for sid in country.STRATEGIES:
            out = [r["host"] for r in states.rank_candidates(rows, cfg(sid))]
            self.assertEqual(out, ["d"], sid)

    def test_extra_blacklist_from_config_holds_too(self):
        c = cfg("speed", blacklist=["ng"])
        self.assertFalse(country.auto_allowed("ng", True, c))
        self.assertIsNone(country.rating("ng", True, c))


class TestAutoBuyGate(unittest.TestCase):
    """Где автоматике РАЗРЕШЕНО покупать (money.buy_candidates)."""

    def test_manual_market_allows_everything_but_blacklist(self):
        """Белого списка нет: человеку в продаже видно всё, кроме чёрного списка."""
        c = cfg("reputation")
        market = money.rank_countries(["ng", "jp", "de", "ru"], c)
        self.assertIn("ng", market)                    # рискованная — но руками можно
        self.assertIn("jp", market)
        self.assertNotIn("ru", market)                 # чёрный список — единственный фильтр
        self.assertLess(market.index("de"), market.index("ng"))   # порядок — внутренний рейтинг
        # автоматике ng при этом нельзя (гейт остался только для авто)
        self.assertFalse(country.auto_allowed("ng", True, c))

    def test_reputation_keeps_old_behaviour(self):
        c = cfg("reputation")
        cands = money.buy_candidates(c, available=["ng", "kz", "jp"])
        self.assertNotIn("ng", cands)                  # рискованные — только вручную
        self.assertNotIn("kz", cands)
        self.assertIn("jp", cands)
        self.assertEqual(cands[:2], ["fi", "ee"])      # trusted вперёд, порядок списка сохранён
        self.assertEqual(cands, money.buy_candidates(
                                                     {"countries": {"whitelist": WL,
                                                                    "strategy": "reputation"}},
                                                     available=["ng", "kz", "jp"]))

    def test_balanced_allows_risky_but_puts_it_last(self):
        cands = money.buy_candidates(cfg("balanced"), available=["ng", "jp"])
        self.assertIn("ng", cands)
        self.assertEqual(cands[-1], "ng")
        self.assertLess(cands.index("jp"), cands.index("ng"))

    def test_speed_allows_everything_in_internal_order(self):
        # авто-гейта у «скорости» нет (вес страны 0 — рейтинг никого не двигает):
        # порядок — внутренний, ближние первыми, страны провайдера в хвосте
        cands = money.buy_candidates(cfg("speed"), available=["ng", "jp"])
        self.assertEqual(cands[0], "fi")
        self.assertEqual(set(cands[-2:]), {"ng", "jp"})


class TestCandidateOrder(unittest.TestCase):
    """В каком порядке перебирать пул (states.rank_candidates)."""

    def rows(self):
        # медленный, но надёжный vs быстрый, но рискованный:
        # ng_fast: 100−5(лат.)+20(tg)+15(оба порта) = базовая 130
        # de_slow: 100−40(лат.) = базовая 60
        return [row("ng_fast", "ng", probe_ok=1, latency_ms=50, tg_ok=1, http_ok=1),
                row("de_slow", "de", probe_ok=1, latency_ms=400)]

    def test_country_first_strategies_prefer_reputation(self):
        for sid in ("reputation",):
            out = [r["host"] for r in states.rank_candidates(self.rows(), cfg(sid))]
            self.assertEqual(out[0], "de_slow", sid)

    def test_speed_prefers_measurements(self):
        out = [r["host"] for r in states.rank_candidates(self.rows(), cfg("speed"))]
        self.assertEqual(out[0], "ng_fast")

    def test_balanced_lets_a_big_gap_win(self):
        # разрыв в замерах 70 против половины репутации (25+25)/2 -> побеждает быстрый
        out = [r["host"] for r in states.rank_candidates(self.rows(), cfg("balanced"))]
        self.assertEqual(out[0], "ng_fast")

    def test_balanced_keeps_reputation_when_measurements_are_close(self):
        # базовые 125 против 120: +5 по замерам не перебивают половину репутации
        rows = [row("ng", "ng", probe_ok=1, latency_ms=100, tg_ok=1, http_ok=1),
                row("de", "de", probe_ok=1, latency_ms=150, tg_ok=1, http_ok=1)]
        out = [r["host"] for r in states.rank_candidates(rows, cfg("balanced"))]
        self.assertEqual(out[0], "de")

    def test_unprobed_candidate_gets_a_chance_in_speed(self):
        """Непробованный не должен навсегда уступать любому измеренному (UNPROBED_SCORE)."""
        # known_bad: базовая 100−40(лат.)−20(shared) = 40 < UNPROBED_SCORE=100
        rows = [row("known_bad", "de", probe_ok=1, latency_ms=400, kind="shared"),
                row("fresh", "de")]
        out = [r["host"] for r in states.rank_candidates(rows, cfg("speed"))]
        self.assertEqual(out, ["fresh", "known_bad"])

    def test_equal_scores_faster_first(self):
        """Приёмка №7: лестница оценки квантует близкие задержки в один балл —
        при равных очках вперёд идёт более быстрый (таблица и ротация едины)."""
        rows = [row("slower", "de", probe_ok=1, latency_ms=925, tg_ok=1, http_ok=1),
                row("faster", "de", probe_ok=1, latency_ms=826, tg_ok=1, http_ok=1)]
        for sid in ("speed", "reputation", "balanced"):
            out = [r["host"] for r in states.rank_candidates(rows, cfg(sid))]
            self.assertEqual(out, ["faster", "slower"], sid)


class TestScoreWeight(unittest.TestCase):
    """Сколько весит страна в оценке пробы (probe.score)."""

    def _row(self):
        return {"kind": "dedicated", "ip_version": 4, "fail_count": 0, "date_end": None,
                "country": "de"}

    def _res(self, cc):
        return {"ok": True, "latency_ms": 200, "tg_ok": True, "socks_ok": True,
                "http_ok": True, "exit_cc": cc, "geo_agree": True}

    def gap(self, strategy):
        r = self._row()
        return (probe.score(r, self._res("de"), cfg=cfg(strategy))
                - probe.score(r, self._res("ng"), cfg=cfg(strategy)))

    def test_weights_scale_the_country_term(self):
        full = country.RATING_TRUSTED - country.RATING_LOW      # 50
        self.assertEqual(self.gap("reputation"), full)
        self.assertEqual(self.gap("balanced"), full / 2)
        self.assertEqual(self.gap("speed"), 0)                  # страна не влияет вообще

    def test_default_config_is_speed(self):
        r, res = self._row(), self._res("ng")
        self.assertEqual(probe.score(r, res), probe.score(r, res, cfg=cfg("speed")))
        self.assertEqual(probe.score(r, res), probe.score(r, res, cfg=None))

    def test_equal_reputation_countries_score_equally(self):
        # fi и us одинаково надёжны — «избранности» больше нет, штрафовать не за что
        r = self._row()
        for sid in country.STRATEGIES:
            self.assertEqual(probe.score(r, self._res("fi"), cfg=cfg(sid)),
                             probe.score(r, self._res("us"), cfg=cfg(sid)), sid)


class TestReputationIsStrategyIndependent(unittest.TestCase):
    """Метка страны в интерфейсе описывает саму страну, а не выбранное правило."""

    def test_tier_does_not_move_with_strategy(self):
        for sid in country.STRATEGIES:
            self.assertEqual(country.tier("de", True, cfg(sid)), "trusted", sid)
            self.assertEqual(country.tier("ng", True, cfg(sid)), "risky", sid)
            self.assertEqual(country.tier("de", False, cfg(sid)), "disputed", sid)

    def test_explain_never_mentions_whitelist(self):
        # понятия «избранных» больше нет — подсказки не должны его воскрешать
        for sid in country.STRATEGIES:
            self.assertNotIn("избранн", country.explain("us", True, cfg(sid)), sid)


class TestPreferenceOrder(unittest.TestCase):
    """Внутренний порядок предпочтения стран (бывший «белый список» — теперь
    константа системы для tie-break'ов, пользователю не показывается)."""

    def test_config_whitelist_ignored(self):
        # старый ключ countries.whitelist в конфиге узла больше ничего не значит
        c = {"countries": {"whitelist": ["jp"]}}
        order = country.preference_order(c)
        self.assertEqual(order[0], "fi")               # константа, не конфиг
        self.assertNotIn("jp", order)

    def test_blacklist_stripped(self):
        c = cfg(blacklist=["de"])
        order = country.preference_order(c)
        self.assertNotIn("de", order)
        self.assertNotIn("ru", order)                  # вечный чёрный список
        self.assertIn("fi", order)


if __name__ == "__main__":
    unittest.main(verbosity=2)
