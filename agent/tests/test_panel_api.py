# -*- coding: utf-8 -*-
"""Пакет A (DEBUG-план 1.3.0): API панели — скрытие запрещённых стран и хардненинг.

П1: /api/pool отдаёт флаг blocked, если ЛЮБАЯ из трёх известных стран строки
(exit_cc по первой geoip-базе, exit_cc_alt по второй, паспортная country) в чёрном
списке — отображение обязано совпадать с автоматикой (probe дисквалифицирует по
любой из баз). Плюс: нечисловой limit в /api/events не должен ронять 500.
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "webpanel"))
import server  # noqa: E402


class TestEventsLimit(unittest.TestCase):
    def test_default(self):
        self.assertEqual(server.events_limit({}), 40)

    def test_non_numeric_falls_back(self):
        # раньше int('abc') давал необработанный 500 (server.py /api/events)
        self.assertEqual(server.events_limit({"limit": ["abc"]}), 40)
        self.assertEqual(server.events_limit({"limit": [""]}), 40)

    def test_numeric_passes(self):
        self.assertEqual(server.events_limit({"limit": ["100"]}), 100)

    def test_caps(self):
        self.assertEqual(server.events_limit({"limit": ["99999"]}), 500)
        # отрицательный LIMIT для sqlite значит «без лимита» — зажимаем снизу
        self.assertEqual(server.events_limit({"limit": ["-5"]}), 1)


class _AppHarness(unittest.TestCase):
    """Живой App на временной БД/конфиге (по образцу test_keys.TestSaveToDisk)."""

    EXTRA_CONFIG = {}

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        secrets = os.path.join(d, "secrets.json")
        with open(secrets, "w", encoding="utf-8") as f:
            json.dump({"admin": {"pw": "x", "totp": "SEED"},
                       "proxy6": {"api_key": "aaaa0bcde1-22222fghi3-4444jklm55"}}, f)
        cfg = os.path.join(d, "config.json")
        conf = {"server": "test", "role": "test", "db": os.path.join(d, "state.db"),
                "ring": os.path.join(d, "cfg"), "server_ip": "127.0.0.1"}
        conf.update(self.EXTRA_CONFIG)
        with open(cfg, "w", encoding="utf-8") as f:
            json.dump(conf, f)
        self._env = (os.environ.get("VPN_PANEL_CONFIG"), os.environ.get("VPN_PANEL_SECRETS"))
        os.environ["VPN_PANEL_CONFIG"] = cfg
        os.environ["VPN_PANEL_SECRETS"] = secrets
        self.app = server.App()
        self._app_saved = server.APP
        server.APP = self.app

    def tearDown(self):
        server.APP = self._app_saved
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

    def put_proxy(self, ext_id, country="fi", exit_cc=None, exit_cc_alt=None, host="10.0.0.1"):
        uid = self.app.pool.upsert_proxy({
            "provider": "proxy6", "ext_id": ext_id, "ip": host, "host": host,
            "port_http": 8080, "port_socks5": 1080, "user": "u", "password": "p",
            "country": country, "ip_version": 4, "kind": "dedicated",
            "date_end": None, "descr": ""})
        self.app.pool.conn.execute(
            "UPDATE proxy SET exit_cc=?, exit_cc_alt=? WHERE uid=?", (exit_cc, exit_cc_alt, uid))
        self.app.pool.conn.commit()
        return uid

    def pool_row(self, uid, cur=None):
        row = self.app.pool.get(uid)
        return server.Handler._pool_row(None, row, cur)


class TestPoolRowBlocked(_AppHarness):
    def test_clean_row_not_blocked(self):
        uid = self.put_proxy("1", country="fi", exit_cc="fi", exit_cc_alt="fi")
        self.assertFalse(self.pool_row(uid)["blocked"])

    def test_blocked_by_exit_cc(self):
        uid = self.put_proxy("2", country="fi", exit_cc="ru")
        self.assertTrue(self.pool_row(uid)["blocked"])

    def test_blocked_by_second_geo_base_only(self):
        # первая база видит fi, вторая ua — probe такую дисквалифицирует по любой
        # из баз, значит и строка обязана прятаться
        uid = self.put_proxy("3", country="fi", exit_cc="fi", exit_cc_alt="ua")
        self.assertTrue(self.pool_row(uid)["blocked"])

    def test_blocked_by_passport_country_only(self):
        uid = self.put_proxy("4", country="by", exit_cc=None, exit_cc_alt=None)
        self.assertTrue(self.pool_row(uid)["blocked"])

    def test_current_row_keeps_flag(self):
        # заблокированный боевой: флаг остаётся, прятать или нет — решает фронт
        uid = self.put_proxy("5", country="ru", host="10.9.9.9")
        r = self.pool_row(uid, cur="10.9.9.9")
        self.assertTrue(r["blocked"])
        self.assertTrue(r["is_current"])


class TestPoolRowBlockedExtendedBlacklist(_AppHarness):
    EXTRA_CONFIG = {"countries": {"blacklist": ["tr"]}}

    def test_config_blacklist_extends(self):
        uid = self.put_proxy("6", country="tr")
        self.assertTrue(self.pool_row(uid)["blocked"])

    def test_hard_block_still_works(self):
        uid = self.put_proxy("7", country="ua")
        self.assertTrue(self.pool_row(uid)["blocked"])

    def test_other_country_untouched(self):
        uid = self.put_proxy("8", country="de", exit_cc="de", exit_cc_alt="de")
        self.assertFalse(self.pool_row(uid)["blocked"])


class _FakeHandler:
    """Хэндлер без HTTP: ответ перехватываем, методы берём у настоящего класса."""

    def _client_ip(self):
        return "127.0.0.1"

    def _json(self, code, obj, extra=None):
        self.resp = (code, obj)

    _do_key_delete = server.Handler._do_key_delete


class TestKeyDelete(_AppHarness):
    """П7: удаление ключа выключает провайдера целиком (gone + баланс + кандидаты)."""

    def setUp(self):
        super().setUp()
        # второй ключ, чтобы «последний ключ» не мешал; кэш балансов обоих
        self.app.save_provider_key("proxyline", "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd")
        self.app.pool.set_setting("balance:proxyline", "12.3 USD")
        self.app.pool.set_setting("balance:proxy6", "500 RUB")
        self.p6 = self.put_proxy("1", host="10.0.0.1")
        self.pl = self.app.pool.upsert_proxy({
            "provider": "proxyline", "ext_id": "9", "ip": "10.0.0.9", "host": "10.0.0.9",
            "port_http": 8080, "port_socks5": 1080, "user": "u", "password": "p",
            "country": "de", "ip_version": 4, "kind": "dedicated",
            "date_end": None, "descr": ""})

    def do_delete(self, name):
        h = _FakeHandler()
        h._do_key_delete(name)
        return h.resp

    def test_delete_marks_gone_and_clears_balance(self):
        code, r = self.do_delete("proxyline")
        self.assertEqual(code, 200)
        self.assertEqual(r["gone_marked"], 1)
        self.assertEqual(self.app.pool.get(self.pl)["gone"], 1, "строки провайдера gone")
        self.assertEqual(self.app.pool.get(self.p6)["gone"], 0, "чужие строки не тронуты")
        self.assertIsNone(self.app.pool.get_setting("balance:proxyline"), "баланс убран")
        self.assertEqual(self.app.pool.get_setting("balance:proxy6"), "500 RUB")
        uids = {x["uid"] for x in self.app.pool.candidates()}
        self.assertNotIn(self.pl, uids, "осиротевшие строки — не кандидаты")
        self.assertIn(self.p6, uids)

    def test_battle_channel_not_cut_but_warned(self):
        # боевой принадлежит удаляемому провайдеру: канал не рвём, но предупреждаем
        sb = os.path.join(self.tmp.name, "singbox.json")
        with open(sb, "w", encoding="utf-8") as f:
            json.dump({"outbounds": [{"tag": "socks-out", "type": "socks",
                                      "server": "10.0.0.9", "server_port": 1080}]}, f)
        self.app.cfg["singbox_config"] = sb
        code, r = self.do_delete("proxyline")
        self.assertEqual(code, 200)
        self.assertIn("продление", r["warning"])
        self.assertEqual(self.app.pool.get(self.pl)["gone"], 1)

    def test_last_key_protected(self):
        self.do_delete("proxyline")
        code, r = self.do_delete("proxy6")
        self.assertEqual(code, 400, "последний ключ убрать нельзя")
        self.assertIn("api_key", (self.app.secrets.get("proxy6") or {}))


if __name__ == "__main__":
    unittest.main(verbosity=2)
