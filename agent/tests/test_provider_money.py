# -*- coding: utf-8 -*-
"""Фаза 2 — провайдеры: валидация ДО API (§15), парсинг buy/prolong/delete/
getprice, идемпотентность транспорта (без перебора доменов на мутациях).
Всё БЕЗ реальных трат: _api застаблен либо http_get_json подменён."""
import unittest

import _ctx
import probe as probe_mod
from providers import base
from providers import proxyline as pl_mod
from providers.base import ProviderError
from providers.proxyline import ProxyLine
from providers.proxy6 import Proxy6, _ids_csv, _validate_descr


# §6.1 — эталонный ЧЁРНЫЙ СПИСОК (решение владельца 2026-08-15: Россия, Украина,
# Беларусь). Дублируется здесь как независимая проверка: если кто-то тронет
# константу в коде — тест упадёт. Сузить список нельзя, расширить можно только
# через config['countries']['blacklist'].
CANON_HARD_BLOCK = {"ru", "ua", "by"}


class StubProxy6(Proxy6):
    """PROXY6 без сети: _api отдаёт заранее заданные ответы и пишет вызовы."""
    def __init__(self, responses=None):
        super().__init__("SECRETKEY123")
        self.responses = responses or {}
        self.calls = []

    def _api(self, method, params=None, mutating=False):
        if method == "ipauth":
            raise RuntimeError("ipauth запрещён")
        self.calls.append((method, dict(params or {}), mutating))
        if method not in self.responses:
            raise AssertionError("неожиданный вызов _api(%r)" % method)
        return self.responses[method]

    def last(self, method):
        return [c for c in self.calls if c[0] == method][-1]


class TestHardBlockSingleSource(unittest.TestCase):
    def test_canon(self):
        self.assertEqual(set(base.HARD_BLOCK_CC), CANON_HARD_BLOCK)

    def test_probe_and_base_agree(self):
        # две независимые копии предохранителя не должны разойтись (§6.1)
        self.assertEqual(set(base.HARD_BLOCK_CC), set(probe_mod.HARD_BLOCK_CC))


class TestBuyValidation(unittest.TestCase):
    """Вся валидация — ДО обращения к API: при отказе _api не вызывается."""
    def setUp(self):
        self.p = StubProxy6({"buy": _ctx.fixture("proxy6_buy.json")})

    def _assert_rejected_before_api(self, **kw):
        base_kw = dict(count=1, period=7, country="fi", version=4)
        base_kw.update(kw)
        with self.assertRaises(ProviderError):
            self.p.buy(**base_kw)
        self.assertEqual(self.p.calls, [], "покупка должна отклоняться ДО вызова API (§15)")

    def test_blacklist_rejected(self):
        for cc in ("ru", "ua", "by"):
            self.p.calls = []
            self._assert_rejected_before_api(country=cc)

    def test_blacklist_rejected_even_if_allow_list_corrupted(self):
        # ГЛАВНОЕ требование §6.1: даже если список разрешённых впишет РФ — не пройдёт
        self.p.calls = []
        with self.assertRaises(ProviderError) as e:
            self.p.buy(count=1, period=7, country="ru", version=4, allow_cc=["ru", "by", "fi"])
        self.assertIn("ЧЁРНОМ СПИСКЕ", str(e.exception))
        self.assertEqual(self.p.calls, [])

    def test_country_outside_allow_list_rejected(self):
        # allow_cc передан явно — сужает до себя
        self.p.calls = []
        with self.assertRaises(ProviderError):
            self.p.buy(count=1, period=7, country="br", version=4, allow_cc=["fi", "de"])
        self.assertEqual(self.p.calls, [])

    def test_any_country_allowed_when_no_allow_list(self):
        """С 2026-08-15 allow_cc=None означает «любая страна вне чёрного списка»:
        где покупать — решает умная оценка выше по стеку, а не жёсткий список."""
        self.p.calls = []
        self.p.buy(count=1, period=7, country="br", version=4)     # не должно бросить
        self.assertEqual(self.p.last("buy")[1]["country"], "br")

    def test_only_version4(self):
        for v in (3, 5, 6, 0, "x"):
            self.p.calls = []
            self._assert_rejected_before_api(version=v)

    def test_count_period_bounds(self):
        self._assert_rejected_before_api(count=0)
        self.p.calls = []
        self._assert_rejected_before_api(count=1000)
        self.p.calls = []
        self._assert_rejected_before_api(period=0)
        self.p.calls = []
        self._assert_rejected_before_api(period=9999)

    def test_bad_descr_rejected(self):
        self._assert_rejected_before_api(descr="x" * 60)
        self.p.calls = []
        self._assert_rejected_before_api(descr="drop; table")  # пробел/;

    def test_valid_buy_reaches_api_without_auto_prolong(self):
        self.p.buy(count=1, period=7, country="fi", version=4, descr="vpnbuy-test-a1b")
        method, params, mutating = self.p.last("buy")
        self.assertTrue(mutating, "buy обязан быть mutating (без перебора доменов)")
        self.assertEqual(params["country"], "fi")
        self.assertEqual(params["version"], 4)
        self.assertNotIn("auto_prolong", params, "auto_prolong НЕ ставим никогда (§6.2)")
        self.assertEqual(params["descr"], "vpnbuy-test-a1b")


class TestBuyParsing(unittest.TestCase):
    def test_parse_and_enrich(self):
        p = StubProxy6({"buy": _ctx.fixture("proxy6_buy.json")})
        r = p.buy(count=1, period=7, country="fi", version=4)
        self.assertEqual(r["order_id"], 777)
        self.assertEqual(r["price"], 28)
        self.assertEqual(r["balance"], 900.0)
        self.assertEqual(len(r["proxies"]), 1)
        n = r["proxies"][0]
        self.assertEqual(n["ext_id"], "40998400")
        self.assertEqual(n["host"], "203.0.113.20")
        # buy не отдаёт version/country в элементах list — подставляем запрошенные
        self.assertEqual(n["ip_version"], 4)
        self.assertEqual(n["kind"], "dedicated")
        self.assertEqual(n["country"], "fi")
        # type auto -> оба протокола на одном порту
        self.assertEqual(n["port_http"], 8000)
        self.assertEqual(n["port_socks5"], 8000)


class TestProlong(unittest.TestCase):
    def test_validation(self):
        p = StubProxy6({"prolong": _ctx.fixture("proxy6_prolong.json")})
        with self.assertRaises(ProviderError):
            p.prolong("40998400; DROP", 30)          # инъекция в ids
        with self.assertRaises(ProviderError):
            p.prolong([], 30)                          # пустой список
        with self.assertRaises(ProviderError):
            p.prolong("40998400", 9999)                # период вне границ
        self.assertEqual(p.calls, [], "невалидное продление не должно доходить до API")

    def test_parse(self):
        p = StubProxy6({"prolong": _ctx.fixture("proxy6_prolong.json")})
        r = p.prolong(["40998400"], 30)
        _, params, mutating = p.last("prolong")
        self.assertTrue(mutating)
        self.assertEqual(params["ids"], "40998400")
        self.assertEqual(params["period"], 30)
        self.assertEqual(r["price"], 120)
        self.assertEqual(r["order_id"], 778)
        self.assertEqual(r["proxies"]["40998400"]["date_end"], "2026-09-20 15:30:00")


class TestDelete(unittest.TestCase):
    def test_ids_only_never_descr(self):
        p = StubProxy6({"delete": _ctx.fixture("proxy6_market.json")["delete"]})
        n = p.delete("40998400")
        method, params, mutating = p.last("delete")
        self.assertTrue(mutating)
        self.assertEqual(set(params.keys()), {"ids"}, "delete НИКОГДА не шлёт descr (§5)")
        self.assertEqual(params["ids"], "40998400")
        self.assertEqual(n, 1)

    def test_empty_and_injection_rejected(self):
        p = StubProxy6({"delete": {"count": 0}})
        with self.assertRaises(ProviderError):
            p.delete([])
        with self.assertRaises(ProviderError):
            p.delete("abc")
        self.assertEqual(p.calls, [])

    def test_ids_csv_helper(self):
        self.assertEqual(_ids_csv([15, 16]), "15,16")
        self.assertEqual(_ids_csv("15, 16"), "15,16")
        with self.assertRaises(ProviderError):
            _ids_csv("")
        with self.assertRaises(ProviderError):
            _ids_csv(["15; rm -rf"])


class TestMarketParsing(unittest.TestCase):
    def setUp(self):
        m = _ctx.fixture("proxy6_market.json")
        self.p = StubProxy6({"getprice": m["getprice"], "getcountry": m["getcountry"],
                             "getcount": m["getcount"]})

    def test_getprice(self):
        r = self.p.getprice(1, 7, 4)
        self.assertEqual(r["price"], 28)
        self.assertEqual(r["currency"], "RUB")

    def test_getcountry_lower(self):
        lst = self.p.getcountry(4)
        self.assertIn("fi", lst)
        self.assertIn("ru", lst, "getcountry отдаёт что есть у сервиса как есть; фильтр — выше")

    def test_getcount(self):
        self.assertEqual(self.p.getcount("fi", 4), 971)
        with self.assertRaises(ProviderError):
            self.p.getcount("finland", 4)   # не iso2


class TestDescrValidation(unittest.TestCase):
    def test_ok(self):
        self.assertEqual(_validate_descr("vpnbuy-node1-20260814T1530-a3f"),
                         "vpnbuy-node1-20260814T1530-a3f")
        self.assertIsNone(_validate_descr(""))
        self.assertIsNone(_validate_descr(None))

    def test_bad(self):
        for bad in ("has space", "x" * 51, "semi;colon", "quote'd"):
            with self.assertRaises(ProviderError):
                _validate_descr(bad)


class TestIpauthGuard(unittest.TestCase):
    def test_ipauth_forbidden(self):
        # предохранитель на РЕАЛЬНОМ _api (срабатывает до сети)
        p = Proxy6("KEY")
        with self.assertRaises(RuntimeError):
            p._api("ipauth", {"ip": "1.2.3.4"})


class TestProxylineProlong(unittest.TestCase):
    """ProxyLine renew — POST /api/renew/ form-encoded (без реальной траты)."""
    def setUp(self):
        self._orig = pl_mod.http_post_form

    def tearDown(self):
        pl_mod.http_post_form = self._orig

    def test_renew_request_shape(self):
        cap = {}

        def fake(url, fields, headers=None, timeout=None, host_label="", **kw):
            cap.update(url=url, fields=fields, headers=headers)
            return {"balance": "59.33", "price": "1.20", "currency": "USD"}
        pl_mod.http_post_form = fake
        r = ProxyLine("PLKEY").prolong(["27039329", "27914928"], 30)
        self.assertTrue(cap["url"].endswith("/api/renew/"))
        self.assertEqual(cap["fields"]["proxies"], ["27039329", "27914928"])
        self.assertEqual(cap["fields"]["period"], 30)
        self.assertEqual(cap["headers"]["API-KEY"], "PLKEY")
        self.assertEqual(r["period"], 30)
        self.assertEqual(r["currency"], "USD")

    def test_validation(self):
        p = ProxyLine("PLKEY")
        for bad in (([], 30), (["abc"], 30), (["1"], 9999), (["1"], 0)):
            with self.assertRaises(ProviderError):
                p.prolong(*bad)


class TestMutatingNoFailover(unittest.TestCase):
    """Мутация (buy) при сетевой ошибке НЕ перебирает второй домен — иначе
    таймаут после успешной покупки = двойная покупка (§6.2)."""
    def setUp(self):
        self._orig = base.http_get_json
        import providers.proxy6 as p6
        self._p6 = p6

    def tearDown(self):
        self._p6.http_get_json = self._orig

    def _install(self):
        calls = []

        def fake(url, headers=None, timeout=None, host_label="", **kw):
            calls.append(host_label)
            raise ProviderError("timeout", network=True)
        self._p6.http_get_json = fake
        return calls

    def test_buy_does_not_failover(self):
        calls = self._install()
        p = Proxy6("KEY")
        with self.assertRaises(ProviderError) as e:
            p.buy(count=1, period=7, country="fi", version=4)
        self.assertTrue(e.exception.network)
        self.assertEqual(len(calls), 1, "buy не должен пробовать второй домен на сетевой ошибке")

    def test_read_does_failover(self):
        calls = self._install()
        p = Proxy6("KEY")
        with self.assertRaises(ProviderError):
            p.getcount("fi", 4)   # чтение -> перебор доменов допустим
        self.assertEqual(len(calls), 2, "чтение обязано перебрать оба домена")


if __name__ == "__main__":
    unittest.main(verbosity=2)
