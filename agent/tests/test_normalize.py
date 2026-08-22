# -*- coding: utf-8 -*-
"""Нормализация ответов обоих провайдеров на фикстурах из доков API."""
import unittest

import _ctx
from providers.proxy6 import norm_proxy6, p6_error_text
from providers.proxyline import norm_proxyline
from providers.proxywing import norm_proxywing


class TestNormProxy6(unittest.TestCase):
    def setUp(self):
        data = _ctx.fixture("proxy6_getproxy.json")
        # ВАЖНО: list у PROXY6 — ОБЪЕКТ с ключами-id, не массив
        self.assertIsInstance(data["list"], dict)
        self.items = list(data["list"].values())

    def test_mtproto_filtered(self):
        norm = [norm_proxy6(it) for it in self.items]
        self.assertIsNone(norm[[it["id"] for it in self.items].index("22")],
                          "version=5 (MTproto) обязан отсеиваться")
        self.assertEqual(len([n for n in norm if n]), 4)

    def test_ipv4_auto(self):
        it = next(x for x in self.items if x["id"] == "21")
        n = norm_proxy6(it)
        self.assertEqual(n["ext_id"], "21")
        self.assertEqual(n["host"], "91.198.74.10")
        # type=auto -> ОБА протокола на одном порту (подарок для RETUNE)
        self.assertEqual(n["port_http"], 62955)
        self.assertEqual(n["port_socks5"], 62955)
        self.assertEqual(n["ip_version"], 4)
        self.assertEqual(n["kind"], "dedicated")
        self.assertEqual(n["country"], "fi")
        self.assertEqual(n["descr"], "vpn-ru")
        self.assertEqual(n["date_end"], "2026-09-01T10:00:00")

    def test_ipv6_host_vs_ip(self):
        it = next(x for x in self.items if x["id"] == "11")
        n = norm_proxy6(it)
        # подключаемся к host (IPv4), ip остаётся справочным IPv6
        self.assertEqual(n["host"], "185.22.134.250")
        self.assertTrue(n["ip"].startswith("2a00:"))
        self.assertEqual(n["ip_version"], 6)
        self.assertEqual(n["kind"], "dedicated")

    def test_shared_http_only(self):
        it = next(x for x in self.items if x["id"] == "23")
        n = norm_proxy6(it)
        self.assertEqual(n["kind"], "shared")
        self.assertEqual(n["port_http"], 8080)
        self.assertIsNone(n["port_socks5"], "type=http не даёт SOCKS-порта")

    def test_error_text(self):
        self.assertIn("IP", p6_error_text({"status": "no", "error_id": 105, "error": "Error ip"}))
        self.assertIn("не принят", p6_error_text({"status": "no", "error_id": 100}))
        self.assertIn("наличии", p6_error_text({"status": "no", "error_id": 300}))
        self.assertIn("денег", p6_error_text({"status": "no", "error_id": 400}))


class TestNormProxyline(unittest.TestCase):
    def setUp(self):
        self.items = _ctx.fixture("proxyline_proxies.json")["results"]

    def test_dedicated(self):
        n = norm_proxyline(self.items[0])
        self.assertEqual(n["provider"], "proxyline")
        self.assertEqual(n["ext_id"], "12345")
        self.assertEqual(n["host"], "11.22.33.44")
        self.assertEqual(n["port_http"], 10000)
        self.assertEqual(n["port_socks5"], 10001)
        self.assertEqual(n["user"], "username")
        self.assertEqual(n["password"], "password")
        self.assertEqual(n["kind"], "dedicated", 'type "1" = dedicated')
        self.assertEqual(n["country"], "ru")
        self.assertEqual(n["descr"], "tag 1")

    def test_shared(self):
        n = norm_proxyline(self.items[1])
        self.assertEqual(n["kind"], "shared", 'type "2" = shared')
        self.assertEqual(n["descr"], "")
        self.assertEqual(n["date_end"], "2022-09-15T14:48:15.355913+03:00")


class TestNormProxyWing(unittest.TestCase):
    def test_datacenter_or_isp_contract(self):
        order = _ctx.fixture("proxywing_proxies.json")["orders"][0]
        n = norm_proxywing(order["proxies"][0], order, "isp")
        self.assertEqual(n["provider"], "proxywing")
        self.assertEqual(n["ext_id"], "isp|ord_test123|prx_test456")
        self.assertEqual(n["host"], "203.0.113.20")
        self.assertEqual((n["port_http"], n["port_socks5"]), (46780, 46781))
        self.assertEqual(n["country"], "fr")
        self.assertEqual(n["ip_version"], 4)
        self.assertEqual(n["kind"], "dedicated")
        self.assertEqual(n["date_end"], "2026-09-22T04:11:04+00:00")


if __name__ == "__main__":
    unittest.main(verbosity=2)
