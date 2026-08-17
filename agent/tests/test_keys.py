# -*- coding: utf-8 -*-
"""Экран «Ключи провайдеров» (§12 GET /api/key/status, POST /api/key).

Зачем тесты именно здесь: ключ приезжает из браузера и уезжает в secrets.json, который
читает ещё и агент. Сломаться это может тремя дорогими способами:
  * ключ утёк обратно в ответ/журнал (показывать можно только хвост);
  * запись ключа затёрла соседние блоки — admin (вход в панель) или второго провайдера;
  * в ключе оказался слеш/пробел, а у PROXY6 ключ подставляется В ПУТЬ URL.
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "webpanel"))
import server  # noqa: E402

# Синтетические ключи той же формы, что у провайдеров. НЕ боевые: реальный ключ
# в тесте пережил бы обезличивание публичной сборки кусками (маска показывает
# хвосты) и ронял бы публичный прогон, когда REPLACE его переписывает (ревью 17.08).
P6_KEY = "aaaa0bcde1-22222fghi3-4444jklm55"          # форма ключа PROXY6
PL_KEY = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd"  # форма ключа ProxyLine


class TestMask(unittest.TestCase):
    def test_long_key_shows_only_tails(self):
        m = server.mask_key(P6_KEY)
        self.assertEqual(m, "aaaa…lm55")
        self.assertNotIn(P6_KEY, m)

    def test_short_key_is_hidden_completely(self):
        self.assertEqual(server.mask_key("abc"), "•••")
        self.assertEqual(server.mask_key("12345678"), "••••••••")

    def test_empty(self):
        self.assertEqual(server.mask_key(""), "")
        self.assertEqual(server.mask_key(None), "")


class TestValidateFormat(unittest.TestCase):
    def test_real_keys_pass(self):
        for k in (P6_KEY, PL_KEY, "abcd1234", "key_with.dots:and-dashes"):
            key, bad = server.validate_key_format(k)
            self.assertIsNone(bad, k)
            self.assertEqual(key, k)

    def test_trims_spaces_around(self):
        key, bad = server.validate_key_format("  %s\n" % P6_KEY)
        self.assertIsNone(bad)
        self.assertEqual(key, P6_KEY)

    def test_empty_rejected(self):
        for k in ("", "   ", None):
            _, bad = server.validate_key_format(k)
            self.assertTrue(bad)

    def test_url_breaking_chars_rejected(self):
        # ключ PROXY6 живёт в пути URL — слеш, «?», «%» и пробел ломают запрос
        for k in ("aaaa/bbbb/cccc", "aaaabbbb?x=1", "aaaa%2Fbbbb", "aaaa bbbb", "aaaa#bbbb",
                  "ключкириллицей", "aaaa\tbbbb"):
            _, bad = server.validate_key_format(k)
            self.assertTrue(bad, k)

    def test_length_bounds(self):
        self.assertTrue(server.validate_key_format("short12")[1])         # 7 символов
        self.assertIsNone(server.validate_key_format("short123")[1])      # 8 — можно
        self.assertTrue(server.validate_key_format("a" * 129)[1])
        self.assertIsNone(server.validate_key_format("a" * 128)[1])


class _StubProvider:
    """Подменяет адаптер провайдера: balance() отдаёт то, что положили в result."""
    name = "stub"
    caps = {"buy": False, "delete": False, "prolong": False, "check": False}
    result = None

    def __init__(self, api_key):
        if not api_key:
            raise ValueError("пустой API-ключ")
        self.api_key = api_key

    def balance(self):
        if isinstance(_StubProvider.result, Exception):
            raise _StubProvider.result
        return _StubProvider.result


class TestCheckKey(unittest.TestCase):
    def setUp(self):
        self._saved = server.PROVIDER_CLASSES
        server.PROVIDER_CLASSES = {"proxy6": _StubProvider}

    def tearDown(self):
        server.PROVIDER_CLASSES = self._saved
        _StubProvider.result = None

    def test_ok_returns_balance(self):
        _StubProvider.result = {"balance": "412.5", "currency": "RUB"}
        ok, info = server.check_key("proxy6", P6_KEY)
        self.assertTrue(ok)
        self.assertEqual(info["balance"], "412.5")
        self.assertEqual(info["currency"], "RUB")

    def test_rejected_key_is_not_network(self):
        _StubProvider.result = server.ProviderError("API-ключ PROXY6 не принят (error 100)", code=100)
        ok, info = server.check_key("proxy6", P6_KEY)
        self.assertFalse(ok)
        self.assertFalse(info["network"])
        self.assertIn("не принят", info["error"])

    def test_no_link_is_network(self):
        # провайдер недоступен с сервера — это не «плохой ключ», панель предложит force
        _StubProvider.result = server.ProviderError("Нет связи с proxy6.net", network=True, unsent=True)
        ok, info = server.check_key("proxy6", P6_KEY)
        self.assertFalse(ok)
        self.assertTrue(info["network"])

    def test_unexpected_exception_does_not_escape(self):
        _StubProvider.result = RuntimeError("что-то совсем неожиданное")
        ok, info = server.check_key("proxy6", P6_KEY)
        self.assertFalse(ok)
        self.assertFalse(info["network"])
        self.assertIn("RuntimeError", info["error"])

    def test_unknown_provider(self):
        ok, info = server.check_key("нет-такого", P6_KEY)
        self.assertFalse(ok)
        self.assertIn("неизвестный провайдер", info["error"])


class TestMerge(unittest.TestCase):
    def base(self):
        return {"admin": {"pw": "scrypt$…", "totp": "SEED", "recovery": ["", "hash2"]},
                "proxy6": {"api_key": P6_KEY},
                "smtp": {"host": "mail.example.com", "to": "you@example.com"}}

    def test_replace_key_keeps_everything_else(self):
        src = self.base()
        out = server.merge_key(src, "proxy6", "aaaa1111-bbbb2222")
        self.assertEqual(out["proxy6"]["api_key"], "aaaa1111-bbbb2222")
        self.assertEqual(out["admin"], src["admin"])
        self.assertEqual(out["smtp"], src["smtp"])

    def test_add_second_provider(self):
        out = server.merge_key(self.base(), "proxyline", PL_KEY)
        self.assertEqual(out["proxyline"]["api_key"], PL_KEY)
        self.assertEqual(out["proxy6"]["api_key"], P6_KEY)

    def test_source_dict_not_mutated(self):
        src = self.base()
        server.merge_key(src, "proxy6", "aaaa1111-bbbb2222")
        self.assertEqual(src["proxy6"]["api_key"], P6_KEY)

    def test_remove_drops_empty_block(self):
        out = server.merge_key(self.base(), "proxy6", None)
        self.assertNotIn("proxy6", out)
        self.assertIn("admin", out)

    def test_remove_keeps_other_fields_of_block(self):
        src = self.base()
        src["proxy6"]["note"] = "кабинет владельца"
        out = server.merge_key(src, "proxy6", "")
        self.assertNotIn("api_key", out["proxy6"])
        self.assertEqual(out["proxy6"]["note"], "кабинет владельца")

    def test_provider_keys_sees_only_real_keys(self):
        self.assertEqual(server.provider_keys(self.base()), {"proxy6"})
        self.assertEqual(server.provider_keys({"proxy6": {"api_key": ""}}), set())
        self.assertEqual(server.provider_keys({"smtp": {"password": "x"}}), set())
        self.assertEqual(server.provider_keys(None), set())
        # именно это условие запрещает убрать последний ключ (панель ослепнет)
        after = server.merge_key(self.base(), "proxy6", None)
        self.assertEqual(server.provider_keys(after), set())


class TestSaveToDisk(unittest.TestCase):
    """Круг «панель → файл → панель»: правка ключа не должна портить остальное."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.secrets = os.path.join(d, "secrets.json")
        with open(self.secrets, "w", encoding="utf-8") as f:
            json.dump({"admin": {"pw": "scrypt$…", "totp": "SEED", "recovery": ["h1", "h2"]},
                       "proxy6": {"api_key": P6_KEY},
                       "smtp": {"host": "mail.example.com", "to": "you@example.com"}}, f)
        cfg = os.path.join(d, "config.json")
        with open(cfg, "w", encoding="utf-8") as f:
            json.dump({"server": "test", "role": "test", "db": os.path.join(d, "state.db"),
                       "ring": os.path.join(d, "cfg"), "server_ip": "127.0.0.1"}, f)
        self._env = (os.environ.get("VPN_PANEL_CONFIG"), os.environ.get("VPN_PANEL_SECRETS"))
        os.environ["VPN_PANEL_CONFIG"] = cfg
        os.environ["VPN_PANEL_SECRETS"] = self.secrets
        self.app = server.App()

    def tearDown(self):
        try:
            self.app.pool.close()
        except Exception:
            pass
        for name, val in zip(("VPN_PANEL_CONFIG", "VPN_PANEL_SECRETS"), self._env):
            if val is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = val
        self.tmp.cleanup()

    def read(self):
        with open(self.secrets, encoding="utf-8") as f:
            return json.load(f)

    def test_replace_key_keeps_admin_and_smtp(self):
        self.app.save_provider_key("proxy6", "aaaa1111-bbbb2222")
        data = self.read()
        self.assertEqual(data["proxy6"]["api_key"], "aaaa1111-bbbb2222")
        self.assertEqual(data["admin"]["totp"], "SEED")
        self.assertEqual(data["admin"]["recovery"], ["h1", "h2"])
        self.assertEqual(data["smtp"]["to"], "you@example.com")

    def test_panel_state_reloaded_without_restart(self):
        self.app.save_provider_key("proxyline", PL_KEY)
        self.assertIn("proxyline", self.app.providers)      # адаптер поднялся сразу
        self.assertEqual(self.app.secrets["proxyline"]["api_key"], PL_KEY)
        self.assertTrue(self.app.provisioned)               # админ на месте, вход не сломался

    def test_removed_key_disables_provider(self):
        self.app.save_provider_key("proxyline", PL_KEY)
        self.app.save_provider_key("proxy6", None)
        self.assertNotIn("proxy6", self.app.providers)
        self.assertNotIn("proxy6", self.read())
        self.assertIn("proxyline", self.app.providers)

    def test_key_written_from_disk_not_from_memory(self):
        """Recovery-код вычёркивает auth мимо APP.secrets — запись копии из памяти
        воскресила бы использованный код (тут это правка файла «со стороны»)."""
        data = self.read()
        data["admin"]["recovery"] = ["", "h2"]              # первый код уже потрачен
        with open(self.secrets, "w", encoding="utf-8") as f:
            json.dump(data, f)
        self.app.save_provider_key("proxy6", "aaaa1111-bbbb2222")
        self.assertEqual(self.read()["admin"]["recovery"], ["", "h2"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
