# -*- coding: utf-8 -*-
"""Фаза 2 — money.py: двойной гейт (тумблер+лимит), суточные лимиты, неснижаемый
остаток, идемпотентность покупки (восстановление по descr, без двойной покупки),
запись в money+журнал, гейты удаления §6.4. БЕЗ реальных трат — провайдер фейковый."""
import os
import multiprocessing
import tempfile
import threading
import unittest

import _ctx
import money
import pool as pool_mod
from providers.base import ProviderError


class FakeProxy6:
    name = "proxy6"
    caps = {"buy": True, "delete": True, "prolong": True, "check": True}

    def __init__(self, price=28.0, balance=928.0, buy_network_fail=False, found=None,
                 check_result=False, currency="RUB"):
        self.price = price
        self.balance_val = balance
        self.currency = currency
        self.buy_network_fail = buy_network_fail
        self.found = found or []
        self.check_result = check_result
        self.buy_calls = self.find_calls = self.delete_calls = 0
        self.attempted_descr = self.find_descr = None

    def getprice(self, count, period, version):
        return {"price": self.price, "price_single": self.price, "period": period,
                "count": count, "balance": self.balance_val, "currency": self.currency}

    def _mk(self, country, descr):
        return {"provider": "proxy6", "ext_id": "50", "ip": "1.2.3.4", "host": "1.2.3.4",
                "port_http": 8000, "port_socks5": 8000, "user": "u", "password": "p",
                "country": country, "ip_version": 4, "kind": "dedicated",
                "date_end": "2026-08-21T10:00:00", "descr": descr}

    def buy(self, count, period, country, version=4, descr=None, allow_cc=None,
            on_submit=None):
        if on_submit is not None:
            on_submit()
        self.buy_calls += 1
        self.attempted_descr = descr
        if self.buy_network_fail:
            raise ProviderError("timeout", network=True)
        return {"proxies": [self._mk(country, descr)], "order_id": 777, "price": self.price,
                "count": 1, "period": period, "country": country,
                "balance": self.balance_val - self.price, "currency": self.currency}

    def find_by_descr(self, descr, state="all"):
        self.find_calls += 1
        self.find_descr = descr
        return [dict(x, descr=descr) for x in self.found]

    def list(self):
        return [self._mk("fi", "")]

    def prolong(self, ids, period, on_submit=None):
        if on_submit is not None:
            on_submit()
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


def _parallel_buy_worker(db_path, start, calls, results, request_id):
    class SharedFake(FakeProxy6):
        def buy(self, *args, **kwargs):
            with calls.get_lock():
                calls.value += 1
            return super().buy(*args, **kwargs)

    pool = pool_mod.Pool(db_path, server="node1")
    try:
        start.wait(10)
        try:
            money.plan_and_buy(
                pool, SharedFake(price=100),
                cfg(max_buys_per_day=1, max_spend_per_day=100),
                country="fi", request_id=request_id)
            results.put("ok")
        except money.SpendDenied:
            results.put("denied")
    finally:
        pool.close()


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

    def test_invalid_price_balance_and_currency_fail_closed(self):
        bad = (
            FakeProxy6(price=float("nan")),
            FakeProxy6(price=float("inf")),
            FakeProxy6(balance=None),
            FakeProxy6(balance=float("nan")),
            FakeProxy6(currency="USD"),
        )
        for provider in bad:
            with self.subTest(price=provider.price, balance=provider.balance_val,
                              currency=provider.currency):
                with self.assertRaises(money.SpendDenied):
                    money.plan_and_buy(self.pool, provider, cfg(), country="fi")
        self.assertEqual(self.money_rows(), [])

    def test_semantically_corrupt_ledger_blocks_before_remote_mutation(self):
        with self.assertRaises(ValueError):
            self.pool.record_money("proxy6", "buy", "proxy6:bad", -100, "RUB")
        self.pool.conn.execute(
            "INSERT INTO money(ts,provider,op,uid,price,currency)"
            " VALUES(date('now'),'proxy6','buy','proxy6:bad',-100,'RUB')")
        self.pool.conn.commit()
        prov = FakeProxy6(price=100)
        with self.assertRaises(money.SpendDenied) as caught:
            money.plan_and_buy(self.pool, prov,
                               cfg(max_spend_per_day=50, max_price_per_buy=150), country="fi")
        self.assertIn("ledger", str(caught.exception))
        self.assertEqual(prov.buy_calls, 0)

    def test_parallel_buy_is_serialized_before_daily_limit_check(self):
        """Two panel/cron callers cannot both pass max_buys_per_day=1."""
        second_pool = pool_mod.Pool(self.db, server="node1")
        entered = threading.Event()
        release = threading.Event()

        class BlockingProvider(FakeProxy6):
            def buy(inner_self, *args, **kwargs):
                entered.set()
                self.assertTrue(release.wait(2), "test release was not signalled")
                return super(BlockingProvider, inner_self).buy(*args, **kwargs)

        first_provider = BlockingProvider()
        first_result = []

        def first():
            first_result.append(money.plan_and_buy(
                self.pool, first_provider, cfg(max_buys_per_day=1), country="fi"))

        worker = threading.Thread(target=first)
        worker.start()
        self.assertTrue(entered.wait(2), "first buy did not reach provider")
        try:
            with self.assertRaises(money.SpendDenied) as caught:
                money.plan_and_buy(second_pool, FakeProxy6(),
                                   cfg(max_buys_per_day=1), country="fi")
            self.assertIn("уже выполняется", str(caught.exception))
        finally:
            release.set()
            worker.join(3)
            second_pool.close()
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(first_result), 1)
        self.assertEqual(len(self.money_rows("buy")), 1)


class TestIdempotency(Base):
    def test_independent_request_ids_each_execute_once(self):
        prov = FakeProxy6(price=20)
        first = money.plan_and_buy(
            self.pool, prov, cfg(), country="fi", request_id="request-independent-fi")
        second = money.plan_and_buy(
            self.pool, prov, cfg(), country="de", request_id="request-independent-de")
        self.assertEqual(first["country"], "fi")
        self.assertEqual(second["country"], "de")
        self.assertNotEqual(first["spend_operation_id"], second["spend_operation_id"])
        self.assertEqual(prov.buy_calls, 2)
        self.assertEqual(len(self.money_rows("buy")), 2)

    def test_same_request_id_cannot_change_intent_or_provider(self):
        prov = FakeProxy6(price=20)
        request_id = "request-bound-to-fi"
        money.plan_and_buy(
            self.pool, prov, cfg(), country="fi", request_id=request_id)
        with self.assertRaises(money.SpendDenied):
            money.plan_and_buy(
                self.pool, prov, cfg(), country="de", request_id=request_id)
        other = FakeProxy6(price=20)
        other.name = "other"
        with self.assertRaises(money.SpendDenied):
            money.plan_and_buy(
                self.pool, other, cfg(), country="fi", request_id=request_id)
        self.assertEqual(prov.buy_calls, 1)
        self.assertEqual(other.buy_calls, 0)

    def test_buy_then_legitimate_prolong_uses_new_request(self):
        prov = FakeProxy6(price=20)
        bought = money.plan_and_buy(
            self.pool, prov, cfg(), country="fi", request_id="request-buy-before-prolong")
        proxy = dict(bought["proxies"][0])
        proxy["uid"] = "proxy6:50"
        prolonged = money.prolong_with_limits(
            self.pool, prov, cfg(), row=proxy, days=30,
            request_id="request-legitimate-prolong")
        self.assertTrue(prolonged["ok"])
        self.assertEqual(len(self.money_rows("buy")), 1)
        self.assertEqual(len(self.money_rows("prolong")), 1)

    def test_acknowledged_request_replays_after_reopen_without_spend(self):
        prov = FakeProxy6(price=20)
        request_id = "request-acked-before-caller-kill"
        first = money.plan_and_buy(
            self.pool, prov, cfg(), country="fi", request_id=request_id)
        self.assertEqual(self.pool.get_spend_operation(
            first["spend_operation_id"])["phase"], "acknowledged")
        self.pool.close()
        self.pool = pool_mod.Pool(self.db, server="node1")
        replay = money.plan_and_buy(
            self.pool, prov, cfg(), country="fi", request_id=request_id)
        self.assertTrue(replay["replayed_request"])
        self.assertEqual(replay["spend_operation_id"], first["spend_operation_id"])
        self.assertEqual(prov.buy_calls, 1)

    def test_planned_request_resumes_exact_intent(self):
        request_id = "request-killed-before-submit"
        op, created = self.pool.begin_spend_operation(
            "buy", "proxy6", {"count": 1, "period": 7, "country": "fi", "version": 4},
            "request-v1:" + request_id, descr="vpnbuy-planned",
            quote_price=20, currency="RUB", balance_before=928)
        self.assertTrue(created)
        prov = FakeProxy6(price=20)
        result = money.plan_and_buy(
            self.pool, prov, cfg(), country="fi", request_id=request_id)
        self.assertEqual(result["spend_operation_id"], op["id"])
        self.assertEqual(prov.buy_calls, 1)
        self.assertEqual(self.pool.get_spend_operation(op["id"])["phase"], "acknowledged")

    def test_kill_before_provider_submit_keeps_planned_request_retryable(self):
        class KillBeforeSubmit(FakeProxy6):
            def __init__(inner_self):
                super().__init__(price=20)
                inner_self.kill_once = True

            def buy(inner_self, count, period, country, version=4, descr=None,
                    allow_cc=None, on_submit=None):
                if inner_self.kill_once:
                    inner_self.kill_once = False
                    raise SystemExit("kill before provider submit callback")
                return super().buy(count, period, country, version, descr, allow_cc,
                                   on_submit=on_submit)

        prov = KillBeforeSubmit()
        request_id = "request-kill-before-remote-submit"
        with self.assertRaises(SystemExit):
            money.plan_and_buy(
                self.pool, prov, cfg(), country="fi", request_id=request_id)
        op = money.bound_spend_request(self.pool, request_id)
        self.assertEqual(op["phase"], "planned")
        result = money.plan_and_buy(
            self.pool, prov, cfg(), country="fi", request_id=request_id)
        self.assertTrue(result["ok"])
        self.assertEqual(prov.buy_calls, 1)
        self.assertEqual(len(self.money_rows("buy")), 1)

    def test_startup_reconcile_preserves_exact_planned_request(self):
        request_id = "request-planned-across-startup"
        self.pool.begin_spend_operation(
            "buy", "proxy6", {"count": 1, "period": 7, "country": "fi", "version": 4},
            "request-v1:" + request_id, descr="vpnbuy-startup-planned",
            quote_price=20, currency="RUB", balance_before=928)
        self.assertEqual(money.reconcile_pending_spend(
            self.pool, {"proxy6": FakeProxy6(price=20)}), [])
        self.assertEqual(money.bound_spend_request(
            self.pool, request_id)["phase"], "planned")
        prov = FakeProxy6(price=20)
        result = money.plan_and_buy(
            self.pool, prov, cfg(), country="fi", request_id=request_id)
        self.assertTrue(result["ok"])
        self.assertEqual(prov.buy_calls, 1)

    def test_planned_quote_drift_becomes_terminal_and_fresh_request_can_spend(self):
        request_id = "request-planned-price-drift"
        op, _created = self.pool.begin_spend_operation(
            "buy", "proxy6", {"count": 1, "period": 7,
                                "country": "fi", "version": 4},
            "request-v1:" + request_id, descr="vpnbuy-price-drift",
            quote_price=20, currency="RUB", balance_before=928)
        prov = FakeProxy6(price=25)
        with self.assertRaises(money.SpendDenied) as caught:
            money.plan_and_buy(
                self.pool, prov, cfg(), country="fi", request_id=request_id)
        self.assertTrue(caught.exception.replace_request)
        self.assertEqual(self.pool.get_spend_operation(op["id"])["phase"], "failed")
        result = money.plan_and_buy(
            self.pool, prov, cfg(), country="fi",
            request_id="request-after-planned-price-drift")
        self.assertTrue(result["ok"])
        self.assertEqual(prov.buy_calls, 1)

    def test_post_submit_http_5xx_stays_ambiguous_and_blocks_new_spend(self):
        class AcceptedThen500(FakeProxy6):
            def __init__(inner_self):
                super().__init__(price=20)
                inner_self.remote_spends = 0

            def buy(inner_self, count, period, country, version=4, descr=None,
                    allow_cc=None, on_submit=None):
                if on_submit is not None:
                    on_submit()
                inner_self.remote_spends += 1
                raise ProviderError("HTTP 500", code=500)

        prov = AcceptedThen500()
        with self.assertRaises(money.SpendDenied) as caught:
            money.plan_and_buy(
                self.pool, prov, cfg(), country="fi",
                request_id="request-accepted-then-http500")
        self.assertFalse(caught.exception.replace_request)
        op = money.bound_spend_request(self.pool, "request-accepted-then-http500")
        self.assertEqual(op["phase"], "submitted")
        with self.assertRaises(money.SpendDenied):
            money.plan_and_buy(
                self.pool, prov, cfg(), country="fi",
                request_id="request-after-ambiguous-http500")
        self.assertEqual(prov.remote_spends, 1)
        self.assertEqual(self.money_rows("buy"), [])

    def test_explicit_definitive_rejection_allows_replacement_request(self):
        class DefinitiveReject(FakeProxy6):
            def buy(inner_self, count, period, country, version=4, descr=None,
                    allow_cc=None, on_submit=None):
                if on_submit is not None:
                    on_submit()
                raise ProviderError("provider rejected", code=400, definitive=True)

        prov = DefinitiveReject(price=20)
        with self.assertRaises(ProviderError) as caught:
            money.plan_and_buy(
                self.pool, prov, cfg(), country="fi",
                request_id="request-definitive-reject")
        self.assertTrue(caught.exception.replace_request)
        self.assertEqual(money.bound_spend_request(
            self.pool, "request-definitive-reject")["phase"], "failed")

    def test_legacy_planned_without_exact_request_is_retired_on_reconcile(self):
        op, _created = self.pool.begin_spend_operation(
            "buy", "proxy6", {"count": 1, "period": 7,
                                "country": "fi", "version": 4},
            "legacy-buy-key", descr="vpnbuy-legacy-planned",
            quote_price=20, currency="RUB", balance_before=928)
        self.assertEqual(money.reconcile_pending_spend(
            self.pool, {"proxy6": FakeProxy6(price=20)}), [])
        self.assertEqual(self.pool.get_spend_operation(op["id"])["phase"], "failed")
        result = money.plan_and_buy(
            self.pool, FakeProxy6(price=20), cfg(), country="fi",
            request_id="request-after-legacy-planned")
        self.assertTrue(result["ok"])

    def test_completed_result_replays_without_current_provider_or_policy(self):
        prov = FakeProxy6(price=20)
        request_id = "request-replay-without-provider"
        first = money.plan_and_buy(
            self.pool, prov, cfg(), country="fi", request_id=request_id)
        replay = money.replay_completed_request(
            self.pool, request_id, "buy",
            expected={"count": 1, "period": 7, "country": "fi", "version": 4})
        self.assertEqual(replay["spend_operation_id"], first["spend_operation_id"])
        self.assertTrue(replay["replayed_request"])
        self.assertEqual(prov.buy_calls, 1)

    @unittest.skipUnless(os.name == "posix", "flock process gate is a Linux contract")
    def test_parallel_processes_do_not_bypass_daily_limit(self):
        self.pool.close()
        ctx = multiprocessing.get_context("fork")
        start = ctx.Event()
        calls = ctx.Value("i", 0)
        results = ctx.Queue()
        workers = [ctx.Process(target=_parallel_buy_worker,
                               args=(self.db, start, calls, results,
                                     "parallel-request-%d" % index))
                   for index in range(2)]
        for worker in workers:
            worker.start()
        start.set()
        for worker in workers:
            worker.join(15)
            self.assertEqual(worker.exitcode, 0)
        outcomes = sorted(results.get(timeout=2) for _ in workers)
        self.assertEqual(outcomes, ["denied", "ok"])
        self.assertEqual(calls.value, 1)
        self.pool = pool_mod.Pool(self.db, server="node1")
        self.assertEqual(len(self.money_rows("buy")), 1)

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

    def test_kill_after_remote_acceptance_recovers_after_reopen_without_second_buy(self):
        class KillAfterAccept(FakeProxy6):
            def __init__(inner_self):
                super().__init__(price=20)
                inner_self.accepted = []
                inner_self.kill_once = True

            def buy(inner_self, count, period, country, version=4, descr=None,
                    allow_cc=None, on_submit=None):
                inner_self.buy_calls += 1
                inner_self.attempted_descr = descr
                inner_self.accepted = [inner_self._mk(country, descr)]
                if inner_self.kill_once:
                    inner_self.kill_once = False
                    if on_submit is not None:
                        on_submit()
                    raise SystemExit("simulated kill after provider acceptance")
                return super().buy(count, period, country, version, descr, allow_cc,
                                   on_submit=on_submit)

            def find_by_descr(inner_self, descr, state="all"):
                inner_self.find_calls += 1
                inner_self.find_descr = descr
                return [dict(item) for item in inner_self.accepted
                        if item.get("descr") == descr]

        prov = KillAfterAccept()
        request_id = "kill-after-provider-acceptance"
        with self.assertRaises(SystemExit):
            money.plan_and_buy(self.pool, prov, cfg(), country="fi",
                               request_id=request_id)
        first_descr = prov.attempted_descr
        self.pool.close()
        self.pool = pool_mod.Pool(self.db, server="node1")
        result = money.plan_and_buy(self.pool, prov, cfg(), country="fi",
                                    request_id=request_id)
        self.assertTrue(result["recovered"])
        self.assertEqual(result["descr"], first_descr)
        self.assertEqual(prov.buy_calls, 1)
        self.assertEqual(len(self.money_rows("buy")), 1)
        phase = self.pool.conn.execute(
            "SELECT phase FROM spend_operation").fetchone()[0]
        self.assertEqual(phase, "acknowledged")

    def test_kill_after_ledger_commit_replays_result_without_second_buy(self):
        prov = FakeProxy6(price=20)
        request_id = "kill-after-ledger-commit"
        original_log = self.pool.log_event

        def kill_on_event(*args, **kwargs):
            raise SystemExit("simulated kill after atomic ledger commit")

        self.pool.log_event = kill_on_event
        with self.assertRaises(SystemExit):
            money.plan_and_buy(self.pool, prov, cfg(), country="fi",
                               request_id=request_id)
        self.pool.log_event = original_log
        self.assertEqual(len(self.money_rows("buy")), 1)
        self.assertEqual(self.pool.conn.execute(
            "SELECT phase FROM spend_operation").fetchone()[0], "committed")
        self.pool.close()
        self.pool = pool_mod.Pool(self.db, server="node1")
        replay = money.plan_and_buy(self.pool, prov, cfg(), country="fi",
                                    request_id=request_id)
        self.assertTrue(replay["recovered"])
        self.assertTrue(replay["replayed_request"])
        self.assertEqual(prov.buy_calls, 1)
        self.assertEqual(len(self.money_rows("buy")), 1)
        # После наблюдаемого replay следующий вызов в том же живом процессе —
        # уже отдельное намерение и может создать новую покупку.
        fresh = money.plan_and_buy(self.pool, prov, cfg(), country="fi",
                                   request_id="independent-fresh-buy")
        self.assertTrue(fresh["ok"])
        self.assertFalse(fresh["recovered"])
        self.assertEqual(prov.buy_calls, 2)
        self.assertEqual(len(self.money_rows("buy")), 2)

    def test_committed_prolong_result_is_never_returned_as_buy(self):
        op, created = self.pool.begin_spend_operation(
            "prolong", "proxy6",
            {"ext_id": "50", "days": 30, "date_before": "2026-08-21T10:00:00"},
            "prolong:cross-kind", uid="proxy6:50", quote_price=20,
            currency="RUB", balance_before=928)
        self.assertTrue(created)
        self.pool.transition_spend_operation(op["id"], "submitted")
        result = {"ok": True, "recovered": False, "uid": "proxy6:50", "days": 30,
                  "price": 20, "currency": "RUB", "balance_after": 908,
                  "date_end": "2026-09-20T10:00:00",
                  "response_discrepancy": [], "spend_operation_id": op["id"]}
        self.pool.complete_spend_operation(
            op["id"], [{"provider": "proxy6", "op": "prolong", "uid": "proxy6:50",
                        "price": 20, "currency": "RUB"}], result=result)
        self.pool.close()
        self.pool = pool_mod.Pool(self.db, server="node1")
        prov = FakeProxy6(price=20)
        with self.assertRaises(money.SpendDenied) as caught:
            money.plan_and_buy(self.pool, prov, cfg(), country="fi")
        self.assertIn("prolong", str(caught.exception))
        self.assertEqual(prov.buy_calls, 0)
        shown = money.resume_spend_operation(self.pool, op["id"])
        self.assertFalse(shown["acknowledged"])
        self.assertEqual(shown["result"]["uid"], "proxy6:50")
        acknowledged = money.resume_spend_operation(
            self.pool, op["id"], acknowledge=True)
        self.assertTrue(acknowledged["acknowledged"])

    def test_corrupt_post_mutation_response_uses_quote_currency_and_positive_price(self):
        class CorruptResponse(FakeProxy6):
            def buy(inner_self, count, period, country, version=4, descr=None,
                    allow_cc=None, on_submit=None):
                result = super().buy(count, period, country, version, descr, allow_cc,
                                     on_submit=on_submit)
                result.update(price=-100, currency="USD")
                return result

        prov = CorruptResponse(price=20)
        result = money.plan_and_buy(
            self.pool, prov, cfg(max_spend_per_day=30), country="fi")
        self.assertEqual(result["price"], 20)
        self.assertEqual(result["currency"], "RUB")
        self.assertEqual(set(result["response_discrepancy"]), {"price", "currency"})
        with self.assertRaises(money.SpendDenied):
            money.plan_and_buy(self.pool, prov, cfg(max_spend_per_day=30), country="fi")
        row = self.money_rows("buy")[0]
        self.assertEqual(row["price"], 20)
        self.assertEqual(row["currency"], "RUB")
        self.assertEqual(prov.buy_calls, 1)

    def test_empty_success_response_stays_unresolved_and_blocks_repeat(self):
        class EmptyResponse(FakeProxy6):
            def buy(inner_self, count, period, country, version=4, descr=None,
                    allow_cc=None, on_submit=None):
                if on_submit is not None:
                    on_submit()
                inner_self.buy_calls += 1
                inner_self.attempted_descr = descr
                return {"proxies": [], "order_id": 7, "price": 100,
                        "balance": 800, "currency": "RUB"}

        prov = EmptyResponse(price=100)
        with self.assertRaises(money.SpendDenied):
            money.plan_and_buy(self.pool, prov, cfg(max_spend_per_day=150), country="fi")
        with self.assertRaises(money.SpendDenied):
            money.plan_and_buy(self.pool, prov, cfg(max_spend_per_day=150), country="fi")
        self.assertEqual(prov.buy_calls, 1)
        self.assertEqual(self.money_rows("buy"), [])
        self.assertEqual(self.pool.pending_spend_operations()[0]["phase"], "submitted")


class TestProlong(Base):
    def test_stale_local_expiry_cannot_confirm_unsuccessful_prolong(self):
        class StaleLocal(FakeProxy6):
            prolong_calls = 0

            def list(inner_self):
                return [dict(inner_self._mk("fi", ""),
                             date_end="2026-09-20T10:00:00")]

            def prolong(inner_self, ids, period, on_submit=None):
                on_submit()
                inner_self.prolong_calls += 1
                raise ProviderError("response lost", network=True)

        provider = StaleLocal()
        row = dict(provider._mk("fi", ""), uid="proxy6:50")
        with self.assertRaises(money.SpendDenied):
            money.prolong_with_limits(self.pool, provider, cfg(), row=row, days=30,
                                      request_id="stale-local-expiry-request")
        self.assertEqual(provider.prolong_calls, 1)
        self.assertEqual(self.money_rows("prolong"), [])
        self.assertEqual(self.pool.pending_spend_operations()[0]["phase"], "submitted")

    def test_unavailable_remote_expiry_denies_before_submit(self):
        provider = FakeProxy6()
        row = dict(provider._mk("fi", ""), uid="proxy6:50")
        provider.list = lambda: []
        submitted = []
        provider.prolong = lambda *args, **kwargs: submitted.append(True)
        with self.assertRaises(money.SpendDenied):
            money.prolong_with_limits(self.pool, provider, cfg(), row=row, days=30)
        self.assertEqual(submitted, [])
        self.assertEqual(self.money_rows("prolong"), [])

    def test_proxyline_is_denied_before_unquoted_mutation(self):
        class EchoOnly(FakeProxy6):
            name = "proxyline"
            prolong_calls = 0

            def list(inner_self):
                return [dict(inner_self._mk("fi", ""), provider="proxyline")]

            def prolong(inner_self, ids, period, on_submit=None):
                on_submit()
                inner_self.prolong_calls += 1
                return {"proxies": [str(ids)], "price": 1.2, "currency": "USD"}

        provider = EchoOnly()
        row = dict(provider.list()[0], uid="proxyline:50")
        with self.assertRaises(money.SpendDenied):
            money.prolong_with_limits(self.pool, provider, cfg(), row=row, days=30,
                                      request_id="unconfirmed-proxyline-request")
        self.assertEqual(provider.prolong_calls, 0)
        self.assertEqual(self.money_rows("prolong"), [])

    def test_proxyline_observed_extension_still_cannot_supply_a_preflight_quote(self):
        class Confirmed(FakeProxy6):
            name = "proxyline"
            prolong_calls = 0
            remote_end = "2026-08-21T10:00:00+00:00"

            def list(inner_self):
                return [dict(inner_self._mk("fi", ""), provider="proxyline",
                             date_end=inner_self.remote_end)]

            def prolong(inner_self, ids, period, on_submit=None):
                on_submit()
                inner_self.prolong_calls += 1
                inner_self.remote_end = "2026-09-20T10:00:00+00:00"
                return {"proxies": [str(ids)], "price": 1.2, "currency": "USD"}

        provider = Confirmed()
        self.pool.upsert_proxy(provider.list()[0], role="auto")
        with self.assertRaises(money.SpendDenied):
            money.prolong_with_limits(
                self.pool, provider, cfg(), row=self.pool.get("proxyline:50"), days=30,
                request_id="confirmed-proxyline-request")
        self.assertEqual(provider.prolong_calls, 0)
        self.assertEqual(self.money_rows("prolong"), [])

    def test_incomparable_expiries_preserve_pending_intent(self):
        provider = FakeProxy6()
        row = dict(provider._mk("fi", ""), uid="proxy6:50")
        original = provider.prolong

        def mismatched_timezone(*args, **kwargs):
            result = original(*args, **kwargs)
            result["proxies"]["50"]["date_end"] = "2026-09-20T10:00:00+00:00"
            return result

        provider.prolong = mismatched_timezone
        with self.assertRaises(money.SpendDenied):
            money.prolong_with_limits(self.pool, provider, cfg(), row=row, days=30)
        self.assertEqual(self.pool.pending_spend_operations()[0]["phase"], "submitted")
        self.assertEqual(self.money_rows("prolong"), [])

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

    def test_invalid_quote_denies_prolong_before_mutation(self):
        row = {"provider": "proxy6", "ext_id": "50", "uid": "proxy6:50", "descr": ""}
        for provider in (FakeProxy6(price=float("nan")), FakeProxy6(balance=None),
                         FakeProxy6(currency="USD")):
            with self.subTest(price=provider.price, balance=provider.balance_val,
                              currency=provider.currency):
                with self.assertRaises(money.SpendDenied):
                    money.prolong_with_limits(
                        self.pool, provider, cfg(max_price_per_buy=200), row=row, days=30)
        self.assertEqual(self.money_rows("prolong"), [])

    def test_kill_after_prolong_acceptance_requires_manual_reconciliation(self):
        class KillAfterAccept(FakeProxy6):
            def __init__(inner_self):
                super().__init__(price=120)
                inner_self.prolong_calls = 0
                inner_self.remote_end = "2026-08-21T10:00:00"

            def prolong(inner_self, ids, period, on_submit=None):
                if on_submit is not None:
                    on_submit()
                inner_self.prolong_calls += 1
                inner_self.remote_end = "2026-09-20T10:00:00"
                raise SystemExit("simulated kill after prolong acceptance")

            def list(inner_self):
                item = inner_self._mk("fi", "")
                item["date_end"] = inner_self.remote_end
                return [item]

        prov = KillAfterAccept()
        request_id = "kill-after-prolong-acceptance"
        self.pool.upsert_proxy({"provider": "proxy6", "ext_id": "50", "ip": "1.2.3.4",
                                "host": "1.2.3.4", "port_http": 8000,
                                "port_socks5": 8000, "user": "u", "password": "p",
                                "country": "fi", "ip_version": 4, "kind": "dedicated",
                                "date_end": "2026-08-21T10:00:00", "descr": ""}, role="auto")
        row = self.pool.get("proxy6:50")
        with self.assertRaises(SystemExit):
            money.prolong_with_limits(self.pool, prov, cfg(max_price_per_buy=200),
                                      row=row, days=30, request_id=request_id)
        self.pool.close()
        self.pool = pool_mod.Pool(self.db, server="node1")
        with self.assertRaises(money.SpendDenied):
            money.prolong_with_limits(
                self.pool, prov, cfg(max_price_per_buy=200),
                row=self.pool.get("proxy6:50"), days=30, request_id=request_id)
        self.assertEqual(prov.prolong_calls, 1)
        self.assertEqual(self.money_rows("prolong"), [])
        self.assertEqual(self.pool.pending_spend_operations()[0]["phase"], "submitted")
        self.assertEqual(self.pool.get("proxy6:50")["date_end"],
                         "2026-08-21T10:00:00")

    def test_unrelated_expiry_change_cannot_reconcile_lost_response(self):
        class ChangedElsewhere(FakeProxy6):
            def __init__(inner_self):
                super().__init__(price=120)
                inner_self.list_calls = 0
                inner_self.prolong_calls = 0

            def list(inner_self):
                inner_self.list_calls += 1
                end = ("2026-08-21T10:00:00" if inner_self.list_calls == 1
                       else "2026-09-20T10:00:00")
                item = inner_self._mk("fi", "")
                item["date_end"] = end
                return [item]

            def prolong(inner_self, ids, period, on_submit=None):
                on_submit()
                inner_self.prolong_calls += 1
                raise ProviderError("response lost", network=True)

        provider = ChangedElsewhere()
        row = dict(provider._mk("fi", ""), uid="proxy6:50")
        with self.assertRaises(money.SpendDenied):
            money.prolong_with_limits(self.pool, provider, cfg(max_price_per_buy=200),
                                      row=row, days=30,
                                      request_id="unrelated-expiry-change")
        self.assertEqual(provider.prolong_calls, 1)
        self.assertEqual(provider.list_calls, 1)
        self.assertEqual(self.money_rows("prolong"), [])
        self.assertEqual(self.pool.pending_spend_operations()[0]["phase"], "submitted")


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
