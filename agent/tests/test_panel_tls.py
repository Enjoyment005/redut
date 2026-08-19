# -*- coding: utf-8 -*-
"""Панель обязана работать по HTTPS на боевом узле (снос №6): пароль/2FA не по HTTP.

Раньше на чистой установке cert выпускался ПОСЛЕ старта панели — при гонке она уходила в
HTTP-фолбэк и обслуживала мастер (пароль, TOTP) открытым текстом. Установщик теперь выпускает
cert до старта (setup_panel.main), а панель на боевом узле отказывается работать без TLS.
"""
import os
import sys
import unittest
from unittest import mock

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


class TestPanelHTTPSServerHandshake(unittest.TestCase):
    """PanelHTTPSServer: TLS-рукопожатие НЕ в главном потоке приёма + таймаут соединения.

    Регресс на зависание node2 19.08: слушающий сокет оборачивался в TLS, из-за чего accept()
    делал рукопожатие в главном потоке — один медленный клиент блокировал приём всех остальных.
    """

    def _server(self):
        # без реального listen(): нам нужны только get_request/атрибуты, не сетевой сокет
        return server.PanelHTTPSServer.__new__(server.PanelHTTPSServer)

    def test_threading_daemon(self):
        self.assertTrue(issubclass(server.PanelHTTPSServer, server.ThreadingHTTPServer))
        self.assertTrue(server.PanelHTTPSServer.daemon_threads)

    def test_get_request_sets_timeout_dev_no_tls(self):
        srv = self._server()
        srv.ssl_ctx = None                      # dev-режим: HTTP без обёртки
        raw = mock.Mock()
        srv.socket = mock.Mock()
        srv.socket.accept.return_value = (raw, ("1.2.3.4", 5555))
        req, addr = srv.get_request()
        self.assertIs(req, raw)                 # сокет не обёрнут
        self.assertEqual(addr, ("1.2.3.4", 5555))
        raw.settimeout.assert_called_once_with(server._CONN_TIMEOUT)

    def test_get_request_defers_handshake(self):
        srv = self._server()
        wrapped = mock.Mock()
        ctx = mock.Mock()
        ctx.wrap_socket.return_value = wrapped
        srv.ssl_ctx = ctx
        raw = mock.Mock()
        srv.socket = mock.Mock()
        srv.socket.accept.return_value = (raw, ("9.9.9.9", 443))
        req, _ = srv.get_request()
        raw.settimeout.assert_called_once_with(server._CONN_TIMEOUT)   # таймаут — на сырой сокет
        args, kwargs = ctx.wrap_socket.call_args
        self.assertIs(args[0], raw)
        self.assertTrue(kwargs.get("server_side"))
        # ключ фикса: рукопожатие ОТЛОЖЕНО — главный поток приёма не блокируется на нём
        self.assertFalse(kwargs.get("do_handshake_on_connect", True))
        self.assertIs(req, wrapped)

    def test_handle_error_silent(self):
        # битые/медленные соединения не должны ронять поток трейсбеком в лог (OPSEC)
        srv = self._server()
        try:
            srv.handle_error(mock.Mock(), ("1.2.3.4", 5555))
        except Exception as e:      # noqa: BLE001
            self.fail("handle_error поднял исключение: %s" % e)


if __name__ == "__main__":
    unittest.main(verbosity=2)
