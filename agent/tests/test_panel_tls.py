# -*- coding: utf-8 -*-
"""Панель обязана работать по HTTPS на боевом узле (снос №6): пароль/2FA не по HTTP.

Раньше на чистой установке cert выпускался ПОСЛЕ старта панели — при гонке она уходила в
HTTP-фолбэк и обслуживала мастер (пароль, TOTP) открытым текстом. Установщик теперь выпускает
cert до старта (setup_panel.main), а панель на боевом узле отказывается работать без TLS.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "webpanel"))
import server  # noqa: E402


class TestRequiresTLS(unittest.TestCase):
    def test_external_ip_requires_tls(self):
        self.assertTrue(server.requires_tls({"server_ip": "198.51.100.10"}))

    def test_loopback_is_dev(self):
        self.assertFalse(server.requires_tls({"server_ip": "127.0.0.1"}))
        self.assertFalse(server.requires_tls({"server_ip": "::1"}))

    def test_empty_is_dev(self):
        self.assertFalse(server.requires_tls({}))
        self.assertFalse(server.requires_tls({"server_ip": ""}))
        self.assertFalse(server.requires_tls({"server_ip": None}))

    def test_whitespace_and_private_lan_still_server(self):
        self.assertFalse(server.requires_tls({"server_ip": "   "}))
        # приватный LAN-адрес — тоже «сервер» (не loopback): TLS обязателен
        self.assertTrue(server.requires_tls({"server_ip": "10.8.0.1"}))


if __name__ == "__main__":
    unittest.main(verbosity=2)
