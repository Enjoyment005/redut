# -*- coding: utf-8 -*-
"""Пакет D (П3): оценка пула считается на лету под ТЕКУЩУЮ стратегию.

Раньше таблица пула показывала колонку score из БД — число, посчитанное той
стратегией, что была активна в момент пробы; смена стратегии ничего не меняла
до следующей перепробы, а UI и автоматика жили в двух разных мирах чисел.
Теперь один источник истины: probe._score_core, поверх — score() (живая проба)
и score_from_row() (строка БД).
"""
import datetime
import unittest

import _ctx      # noqa: F401
import probe
import states


def _in(days):
    return (datetime.datetime.now() + datetime.timedelta(days=days)).replace(
        microsecond=0).isoformat(sep=" ")


def cfg_strategy(name):
    return {"countries": {"strategy": name}}


def make_row(**kw):
    """Строка пула после успешной пробы (как её записал record_probe)."""
    row = {"uid": "proxy6:1", "provider": "proxy6", "ext_id": "1", "host": "1.1.1.1",
           "probe_ok": 1, "socks_ok": 1, "http_ok": 1, "tg_ok": 1,
           "latency_ms": 200, "fail_count": 0, "kind": "dedicated", "ip_version": 4,
           "date_end": _in(10), "exit_cc": "fi", "exit_cc_alt": "fi", "geo_agree": 1,
           "country": "fi", "role": "auto", "score": None, "gone": 0,
           "cooldown_until": None}
    row.update(kw)
    return row


class TestParity(unittest.TestCase):
    """score() после живой пробы и score_from_row() на одинаковых входах совпадают."""

    def test_same_inputs_same_score(self):
        for strat in ("whitelist", "reputation", "balanced", "speed"):
            cfg = cfg_strategy(strat)
            row_pre = {"fail_count": 0, "kind": "dedicated", "ip_version": 4,
                       "date_end": _in(10), "country": "fi"}
            res = {"ok": True, "latency_ms": 200, "tg_ok": True, "socks_ok": True,
                   "http_ok": True, "exit_cc": "fi", "geo_agree": True}
            live = probe.score(row_pre, res, is_current=False, cfg=cfg)
            stored = make_row()
            full, _base = probe.score_from_row(stored, cfg)
            self.assertEqual(live, full, "стратегия %s: формула разошлась" % strat)

    def test_current_bonus_matches(self):
        live = probe.score({"fail_count": 0, "kind": "dedicated", "ip_version": 4,
                            "date_end": _in(10), "country": "fi"},
                           {"ok": True, "latency_ms": 200, "tg_ok": True, "socks_ok": True,
                            "http_ok": True, "exit_cc": "fi", "geo_agree": True},
                           is_current=True)
        full, _ = probe.score_from_row(make_row(), is_current=True)
        self.assertEqual(live, full)

    def test_failed_probe_is_none(self):
        self.assertEqual(probe.score_from_row(make_row(probe_ok=0)), (None, None))


class TestStrategyChangesScoreInstantly(unittest.TestCase):
    def test_country_weight_follows_strategy(self):
        row = make_row(exit_cc="fi")           # trusted: +25 при весе 1.0
        full_rep, base_rep = probe.score_from_row(row, cfg_strategy("reputation"))
        full_speed, base_speed = probe.score_from_row(row, cfg_strategy("speed"))
        self.assertEqual(base_rep, base_speed, "базовая часть от стратегии не зависит")
        self.assertEqual(full_rep - base_rep, 25.0)
        self.assertEqual(full_speed, base_speed, "у «скорости» вес страны 0")

    def test_balanced_half_weight(self):
        row = make_row(exit_cc="fi")
        full, base = probe.score_from_row(row, cfg_strategy("balanced"))
        self.assertEqual(full - base, 12.5)

    def test_expiry_penalty_drifts_without_new_probe(self):
        # штраф «<2 дней» считается от НАСТОЯЩЕГО времени, а не от времени пробы —
        # фиксируем фичу: тот же замер, разный date_end -> разница ровно 30
        fresh, _ = probe.score_from_row(make_row(date_end=_in(10)))
        dying, _ = probe.score_from_row(make_row(date_end=_in(1)))
        self.assertEqual(fresh - dying, 30.0)


class TestRankConsistency(unittest.TestCase):
    """rank_candidates и порядок/оценки пула согласованы при каждой стратегии."""

    def rows(self):
        # fi: надёжная страна, медленный (base ниже); ng: рискованная, быстрый
        fi = make_row(uid="proxy6:fi", host="1.1.1.1", exit_cc="fi", country="fi",
                      latency_ms=400, tg_ok=0)
        ng = make_row(uid="proxy6:ng", host="2.2.2.2", exit_cc="ng", country="ng",
                      latency_ms=50, tg_ok=1)
        return [fi, ng]

    def order(self, strat):
        return [r["uid"] for r in states.rank_candidates(self.rows(), cfg_strategy(strat))]

    def test_reputation_country_first(self):
        self.assertEqual(self.order("reputation"), ["proxy6:fi", "proxy6:ng"])

    def test_speed_measures_first(self):
        self.assertEqual(self.order("speed"), ["proxy6:ng", "proxy6:fi"])

    def test_balanced_sum_decides(self):
        # fi: base=100-40+15+10=85, страна +12.5 -> 97.5
        # ng: base=100-5+20+15+10=140, страна -12.5 -> 127.5
        self.assertEqual(self.order("balanced"), ["proxy6:ng", "proxy6:fi"])

    def test_rank_uses_same_numbers_as_pool_view(self):
        # в режимах сумм ключ ранжирования == полной оценке score_from_row
        for strat in ("balanced", "speed"):
            cfg = cfg_strategy(strat)
            fulls = {r["uid"]: probe.score_from_row(r, cfg)[0] for r in self.rows()}
            expect = [u for u, _ in sorted(fulls.items(), key=lambda t: -t[1])]
            self.assertEqual(self.order(strat), expect, strat)

    def test_country_not_double_counted_in_country_first(self):
        # два прокси одной страны: порядок решает БАЗОВАЯ часть (замеры), и добавка
        # страны не влияет на их относительный порядок
        a = make_row(uid="proxy6:a", host="1.1.1.1", latency_ms=50)     # быстрее
        b = make_row(uid="proxy6:b", host="2.2.2.2", latency_ms=400, tg_ok=0)
        got = [r["uid"] for r in states.rank_candidates([b, a], cfg_strategy("reputation"))]
        self.assertEqual(got, ["proxy6:a", "proxy6:b"])

    def test_unprobed_gets_unprobed_score_in_sum_modes(self):
        # непробованный (probe_ok=0) в режиме сумм получает cr+UNPROBED_SCORE=100:
        # обгоняет измеренный с полной оценкой < 100, уступает измеренному > 100
        weak = make_row(uid="proxy6:weak", host="3.3.3.3", latency_ms=390, tg_ok=0,
                        socks_ok=1, http_ok=0, kind="shared", exit_cc="kz")
        fresh = make_row(uid="proxy6:new", host="4.4.4.4", probe_ok=0, exit_cc=None,
                         country=None, latency_ms=None)
        got = [r["uid"] for r in states.rank_candidates([weak, fresh], cfg_strategy("speed"))]
        self.assertEqual(got, ["proxy6:new", "proxy6:weak"],
                         "свежекупленный должен получить шанс раньше заведомо слабого")

    def test_blacklist_dropped_everywhere(self):
        bad = make_row(uid="proxy6:ru", host="5.5.5.5", exit_cc="ru", country="ru")
        for strat in ("whitelist", "reputation", "balanced", "speed"):
            got = [r["uid"] for r in states.rank_candidates(self.rows() + [bad],
                                                            cfg_strategy(strat))]
            self.assertNotIn("proxy6:ru", got, strat)

    def test_geo_dispute_penalised_in_country_first_order(self):
        # ревью 1.3.0: штраф «geoip-базы разошлись» обязан влиять и на ПОРЯДОК
        # перебора (не только на отображаемую оценку) — спорный IP с лучшими
        # замерами не должен обгонять чистый той же страны
        clean = make_row(uid="proxy6:clean", host="1.1.1.1", latency_ms=300, tg_ok=0)
        disputed = make_row(uid="proxy6:disp", host="2.2.2.2", latency_ms=50,
                            geo_agree=0, exit_cc_alt="us")
        got = [r["uid"] for r in states.rank_candidates([disputed, clean],
                                                        cfg_strategy("reputation"))]
        self.assertEqual(got, ["proxy6:clean", "proxy6:disp"])


class TestPoolViewOrder(unittest.TestCase):
    """Порядок таблицы пула = порядку ротации; чёрный список — в конец."""

    def test_matches_rank_and_pushes_blacklist_last(self):
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "webpanel"))
        import server
        fi = make_row(uid="proxy6:fi", host="1.1.1.1", exit_cc="fi", latency_ms=400, tg_ok=0)
        ng = make_row(uid="proxy6:ng", host="2.2.2.2", exit_cc="ng", country="ng", latency_ms=50)
        ru = make_row(uid="proxy6:ru", host="5.5.5.5", exit_cc="ru", country="ru")
        cfg = cfg_strategy("reputation")
        got = [r["uid"] for r in server.pool_view_order([ru, ng, fi], cfg)]
        ranked = [r["uid"] for r in states.rank_candidates([ru, ng, fi], cfg)]
        self.assertEqual(got, ranked + ["proxy6:ru"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
