# -*- coding: utf-8 -*-
"""Фаза 2 — money.py: двойной гейт (тумблер+лимит), суточные лимиты, неснижаемый
остаток, идемпотентность покупки (восстановление по descr, без двойной покупки),
запись в money+журнал, гейты удаления §6.4. БЕЗ реальных трат — провайдер фейковый."""
import os
import tempfile
import unittest

import _ctx
import money
import pool as pool_mod
from providers.base import ProviderError


class FakeProxy6:
    name = "proxy6"
    caps = {"buy": True, "delete": True, "prolong": True, "check": True}

    def __init__(self, price=28.0, balance=928.0, buy_network_fail=False, found=None,
                 check_result=False):
        self.price = price
        self.balance_val = balance
        self.buy_network_fail = buy_network_fail
        self.found = found or []
        self.check_result = check_result
        self.buy_calls = self.find_calls = self.delete_calls = 0
        self.attempted_descr = self.find_descr = None

    def getprice(self, count, period, version):
        return {"price": self.price, "price_single": self.price, "period": period,
                "count": count, "balance": self.balance_val, "currency": "RUB"}

    def _mk(self, country, descr):
        return {"provider": "proxy6", "ext_id": "50", "ip": "1.2.3.4", "host": "1.2.3.4",
                "port_http": 8000, "port_socks5": 8000, "user": "u", "password": "p",
                "country": country, "ip_version": 4, "kind": "dedicated",
                "date_end": "2026-08-21T10:00:00", "descr": descr}

    def buy(self, count, period, country, version=4, descr=None, allow_cc=None):
        self.buy_calls += 1
        self.attempted_descr = descr
        if self.buy_network_fail:
            raise ProviderError("timeout", network=True)
        return {"proxies": [self._mk(country, descr)], "order_id": 777, "price": self.price,
                "count": 1, "period": period, "country": country,
                "balance": self.balance_val - self.price, "currency": "RUB"}

    def find_by_descr(self, descr, state="all"):
        self.find_calls += 1
        self.find_descr = descr
        return [dict(x, descr=descr) for x in self.found]

    def prolong(self, ids, period):
        ext = str(ids if isinstance(ids, (str, int)) else ids[0])
        return {"order_id": 778, "price": self.price, "count": 1, "period": period,
                "balance": self.balance_val - self.price, "currency": "RUB",
                "proxies": {ext: {"date_end": "2026-09-20 10:00:00"}}}

    def delete(self, ids):
        self.delete_calls += 1
        return 1

    def check(self, ext_id):
        return self.check_result

    def balance(self):
        return {"balance": self.balance_val, "currency": "RUB"}


def cfg(**money_over):
    m = {"buy_enabled": True, "delete_enabled": False, "max_buys_per_day": 3,
         "max_spend_per_day": 300, "max_price_per_buy": 150, "min_balance_reserve": 300,
         "buy_period_days": 7, "buy_version": 4, "currency": "RUB"}
    m.update(money_over)
    return {"server": "node1", "money": m,
            "countries": {"strategy": "reputation",
                          "whitelist": ["fi", "de", "ru"]}}   # ru нарочно — должен вычищаться


class Base(unittest.TestCase):
    def setUp(self):
        fd, self.db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.pool = pool_mod.Pool(self.db, server="node1")

    def tearDown(self):
        self.pool.close()
        os.unlink(self.db)

    def money_rows(self, op=None):
        q = "SELECT provider,op,uid,price,currency FROM money"
        if op:
            q += " WHERE op='%s'" % op
        return self.pool.conn.execute(q).fetchall()

    def events(self, action):
        return self.pool.conn.execute(
            "SELECT result,detail FROM event WHERE action=? ORDER BY id", (action,)).fetchall()


class TestConfig(Base):
    def test_market_ranking_strips_blacklisted(self):
        # «что в продаже» для человека: всё, кроме чёрного списка (белого нет)
        market = money.rank_countries(["fi", "ru", "ng"], cfg())
        self.assertIn("fi", market)
        self.assertIn("ng", market, "рискованную страну руками купить можно")
        self.assertNotIn("ru", market, "чёрный список вычищается всегда (§6.1)")
        self.assertEqual(market[0], "fi", "порядок — внутренний рейтинг")

    def test_buy_candidates_ranked_by_rating(self):
        """Порядок покупки задаёт умная оценка: надёжные страны раньше рискованных,
        а страны с низкой оценкой автоматика не берёт вовсе."""
        cands = money.buy_candidates(cfg(), available=["ng", "kz", "jp", "de"])
        self.assertIn("de", cands)
        self.assertIn("jp", cands)
        self.assertNotIn("ng", cands, "рискованная страна — не для авто-покупки")
        self.assertNotIn("kz", cands)
        self.assertNotIn("ru", cands, "чёрный список не попадает никогда")
        self.assertLess(cands.index("de"), cands.index("jp"), "ЕС раньше прочих развитых")

    def test_gen_descr(self):
        d = money.gen_descr("node1")
        self.assertTrue(d.startswith("vpnbuy-node1-"))
        self.assertLessEqual(len(d), 50)
        self.assertTrue(money.gen_descr("a/b c!") .startswith("vpnbuy-abc-"))
        # два вызова -> разные (случайный суффикс)
        self.assertNotEqual(money.gen_descr("x"), money.gen_descr("x"))


class TestBuyGates(Base):
    def test_success_records_money_and_event(self):
        prov = FakeProxy6()
        r = money.plan_and_buy(self.pool, prov, cfg(), country="fi")
        self.assertTrue(r["ok"])
        self.assertFalse(r["recovered"])
        self.assertEqual(prov.buy_calls, 1)
        rows = self.money_rows("buy")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["uid"], "proxy6:50")
        self.assertEqual(rows[0]["currency"], "RUB")
        self.assertEqual(self.events("buy")[-1][0], "ok")

    def test_toggle_off(self):
        with self.assertRaises(money.SpendDenied):
            money.plan_and_buy(self.pool, FakeProxy6(), cfg(buy_enabled=False), country="fi")
        self.assertEqual(self.money_rows(), [])

    def test_low_rated_country_denied_for_automation(self):
        """Автоматика не покупает страны с низкой оценкой (Нигерия, СНГ-соседи)."""
        with self.assertRaises(money.SpendDenied) as e:
            money.plan_and_buy(self.pool, FakeProxy6(), cfg(), country="ng", auto=True)
        self.assertIn("низкой оценкой", str(e.exception))
        self.assertEqual(self.money_rows(), [])

    def test_low_rated_country_allowed_for_human(self):
        """Человек из панели может купить такую страну осознанно (auto=False)."""
        r = money.plan_and_buy(self.pool, FakeProxy6(), cfg(), country="ng", auto=False)
        self.assertTrue(r["ok"])

    def test_country_outside_whitelist_is_fine_now(self):
        """Белый список больше не жёсткий фильтр: Бразилии в нём нет, но она
        не запрещена — просто с низкой оценкой, значит только вручную."""
        r = money.plan_and_buy(self.pool, FakeProxy6(), cfg(), country="br", auto=False)
        self.assertTrue(r["ok"])
        with self.assertRaises(money.SpendDenied):
            money.plan_and_buy(self.pool, FakeProxy6(), cfg(), country="br", auto=True)

    def test_blacklisted_country_blocked_always(self):
        # ru есть в конфиге whitelist, но чёрный список сильнее -> отказ в обоих режимах
        for auto in (True, False):
            with self.assertRaises(money.SpendDenied) as e:
                money.plan_and_buy(self.pool, FakeProxy6(), cfg(), country="ru", auto=auto)
            self.assertIn("чёрном списке", str(e.exception))
        self.assertEqual(self.money_rows(), [])

    def test_blacklist_extendable_via_config(self):
        """Список можно расширить конфигом (сузить — нельзя, это код)."""
        c = cfg()
        c["countries"]["blacklist"] = ["de"]
        with self.assertRaises(money.SpendDenied):
            money.plan_and_buy(self.pool, FakeProxy6(), c, country="de", auto=False)
        # а базовые три запрещены и без конфига
        self.assertTrue(all(money.country_mod.is_blocked(cc) for cc in ("ru", "ua", "by")))

    def test_per_buy_price_limit(self):
        with self.assertRaises(money.SpendDenied) as e:
            money.plan_and_buy(self.pool, FakeProxy6(price=200.0), cfg(max_price_per_buy=150),
                               country="fi")
        self.assertIn("покупк", str(e.exception))
        self.assertEqual(self.money_rows(), [])

    def test_daily_count_limit(self):
        prov = FakeProxy6()
        c = cfg(max_buys_per_day=2)
        money.plan_and_buy(self.pool, prov, c, country="fi")
        money.plan_and_buy(self.pool, prov, c, country="fi")
        with self.assertRaises(money.SpendDenied) as e:
            money.plan_and_buy(self.pool, prov, c, country="fi")
        self.assertIn("сутки", str(e.exception))
        self.assertEqual(len(self.money_rows("buy")), 2, "третья покупка не записана")

    def test_daily_spend_limit(self):
        prov = FakeProxy6(price=100.0)
        c = cfg(max_spend_per_day=250, max_price_per_buy=200)
        money.plan_and_buy(self.pool, prov, c, country="fi")   # 100
        money.plan_and_buy(self.pool, prov, c, country="fi")   # 200
        with self.assertRaises(money.SpendDenied):             # 300 > 250
            money.plan_and_buy(self.pool, prov, c, country="fi")
        self.assertEqual(len(self.money_rows("buy")), 2)

    def test_balance_floor(self):
        # баланс 928, цена 28 -> после 900; остаток 910 -> 900 < 910 -> отказ
        with self.assertRaises(money.SpendDenied) as e:
            money.plan_and_buy(self.pool, FakeProxy6(balance=928.0, price=28.0),
                               cfg(min_balance_reserve=910), country="fi")
        self.assertIn("остатк", str(e.exception))
        self.assertEqual(self.money_rows(), [])


class TestIdempotency(Base):
    def test_recovered_by_descr_no_double_buy(self):
        # buy оборвался сетью, но прокси нашёлся по descr -> покупка засчитана,
        # buy НЕ повторяется, запись одна
        found = [{"provider": "proxy6", "ext_id": "50", "ip": "1.2.3.4", "host": "1.2.3.4",
                  "port_http": 8000, "port_socks5": 8000, "user": "u", "password": "p",
                  "country": "fi", "ip_version": 4, "kind": "dedicated",
                  "date_end": "2026-08-21T10:00:00", "descr": ""}]
        prov = FakeProxy6(buy_network_fail=True, found=found)
        r = money.plan_and_buy(self.pool, prov, cfg(), country="fi")
        self.assertTrue(r["recovered"])
        self.assertEqual(prov.buy_calls, 1, "buy вызван ровно один раз (без повтора)")
        self.assertEqual(prov.find_calls, 1, "проверка по descr выполнена")
        self.assertEqual(prov.attempted_descr, prov.find_descr, "descr для buy и поиска — один")
        self.assertEqual(len(self.money_rows("buy")), 1)
        self.assertEqual(self.events("buy")[-1][0], "recovered")

    def test_unconfirmed_no_record_no_double(self):
        prov = FakeProxy6(buy_network_fail=True, found=[])   # не нашёлся по descr
        with self.assertRaises(money.SpendDenied) as e:
            money.plan_and_buy(self.pool, prov, cfg(), country="fi")
        self.assertIn("НЕ подтверждена", str(e.exception))
        self.assertEqual(prov.buy_calls, 1, "buy НЕ повторяется даже когда не подтверждён")
        self.assertEqual(self.money_rows(), [], "неподтверждённая покупка не пишется в money")
        self.assertEqual(self.events("buy")[-1][0], "unconfirmed")


class TestProlong(Base):
    def test_records_and_updates_date_end(self):
        prov = FakeProxy6(price=120.0)
        self.pool.upsert_proxy({"provider": "proxy6", "ext_id": "50", "ip": "1.2.3.4",
                                "host": "1.2.3.4", "port_http": 8000, "port_socks5": 8000,
                                "user": "u", "password": "p", "country": "fi", "ip_version": 4,
                                "kind": "dedicated", "date_end": "2026-08-21T10:00:00",
                                "descr": ""}, role="auto")
        row = self.pool.get("proxy6:50")
        r = money.prolong_with_limits(self.pool, prov, cfg(max_price_per_buy=200), row=row, days=30)
        self.assertEqual(r["days"], 30)
        self.assertEqual(len(self.money_rows("prolong")), 1)
        self.assertEqual(self.pool.get("proxy6:50")["date_end"], "2026-09-20T10:00:00")

    def test_toggle_off_blocks_prolong(self):
        prov = FakeProxy6()
        self.pool.upsert_proxy({"provider": "proxy6", "ext_id": "50", "ip": "1.2.3.4",
                                "host": "1.2.3.4", "port_http": 8000, "port_socks5": 8000,
                                "user": "u", "password": "p", "country": "fi", "ip_version": 4,
                                "kind": "dedicated", "date_end": "", "descr": ""}, role="auto")
        row = self.pool.get("proxy6:50")
        with self.assertRaises(money.SpendDenied):
            money.prolong_with_limits(self.pool, prov, cfg(buy_enabled=False), row=row, days=30)

    def test_provider_mismatch_denied(self):
        # C5 (ревью 1.3.0): адаптер proxy6 против строки proxyline — ext_id чужой,
        # продление отклоняется ДО обращения к API
        prov = FakeProxy6()
        row = {"provider": "proxyline", "ext_id": "50", "uid": "proxyline:50", "descr": ""}
        with self.assertRaises(money.SpendDenied):
            money.prolong_with_limits(self.pool, prov, cfg(max_price_per_buy=200), row=row, days=30)
        self.assertEqual(self.money_rows("prolong"), [], "денег не записано — траты не было")


class TestCanDelete(unittest.TestCase):
    def row(self, **kw):
        r = {"role": "auto", "host": "1.2.3.4", "fail_count": 2, "provider": "proxy6",
             "ext_id": "50", "uid": "proxy6:50"}
        r.update(kw)
        return r

    def test_toggle_off_default(self):
        ok, why = money.can_delete(self.row(), cfg())   # delete_enabled False по умолч.
        self.assertFalse(ok)
        self.assertIn("тумблер", why)

    def test_all_conditions_met(self):
        ok, why = money.can_delete(self.row(), cfg(delete_enabled=True),
                                   current_host="9.9.9.9", provider_check=False)
        self.assertTrue(ok, why)

    def test_off_role_deletable_by_human(self):
        # П9 (роли v2): ролевого гейта нет — off/auto оба удаляемы (человек — хозяин);
        # защита боевого/провалов/check остаётся
        ok, why = money.can_delete(self.row(role="off"), cfg(delete_enabled=True),
                                   current_host="9.9.9.9", provider_check=False)
        self.assertTrue(ok, why)

    def test_current_upstream_protected(self):
        ok, why = money.can_delete(self.row(), cfg(delete_enabled=True),
                                   current_host="1.2.3.4", provider_check=False)
        self.assertFalse(ok)
        self.assertIn("upstream", why)

    def test_fail_count_below_min(self):
        ok, _ = money.can_delete(self.row(fail_count=1), cfg(delete_enabled=True),
                                 current_host="9.9.9.9", provider_check=False)
        self.assertFalse(ok)

    def test_provider_check_must_be_false(self):
        for chk in (True, None):
            ok, _ = money.can_delete(self.row(), cfg(delete_enabled=True),
                                     current_host="9.9.9.9", provider_check=chk)
            self.assertFalse(ok, "check провайдера должен быть именно False")


class TestDeleteRecord(Base):
    def test_records_money(self):
        prov = FakeProxy6()
        row = {"role": "auto", "provider": "proxy6", "ext_id": "50", "uid": "proxy6:50",
               "descr": "", "host": "1.2.3.4"}
        n = money.delete_and_record(self.pool, prov, row, currency="RUB", balance_after=928.0)
        self.assertEqual(n, 1)
        self.assertEqual(len(self.money_rows("delete")), 1)


class TestStoreBalance(Base):
    """store_balance: единый писатель setting balance:<name>. Баг 19.08 — крон
    pool-refresh баланс не сохранял, панель показывала пусто до ручного клика."""

    def test_writes_setting(self):
        ok = money.store_balance(self.pool, "proxy6", {"balance": "2308.01", "currency": "RUB"})
        self.assertTrue(ok)
        self.assertEqual(self.pool.get_setting("balance:proxy6"), "2308.01 RUB")

    def test_missing_amount_keeps_previous(self):
        self.pool.set_setting("balance:proxy6", "500 RUB")
        # провайдер молчит суммой — прежний баланс НЕ затираем «None»
        self.assertFalse(money.store_balance(self.pool, "proxy6", {"currency": "RUB"}))
        self.assertFalse(money.store_balance(self.pool, "proxy6", None))
        self.assertFalse(money.store_balance(self.pool, "proxy6", {"balance": "", "currency": "RUB"}))
        self.assertEqual(self.pool.get_setting("balance:proxy6"), "500 RUB")

    def test_no_currency_no_trailing_space(self):
        money.store_balance(self.pool, "proxyline", {"balance": "12.3"})
        self.assertEqual(self.pool.get_setting("balance:proxyline"), "12.3")


if __name__ == "__main__":
    unittest.main(verbosity=2)
