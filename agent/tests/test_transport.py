# -*- coding: utf-8 -*-
"""providers/base: транспорт к API провайдера — напрямую или через канал узла (tun0).

Найдено на приёмке 15.08 (снос №4): с российского VPS домены PROXY6 недоступны напрямую
(SNI-блокировка), а через собственный канал узла API отвечает. Правила безопасности для денег:
повтор другим транспортом — только если запрос заведомо не был доставлен (unsent).
"""
import os
import tempfile
import unittest
import urllib.error

import _ctx  # noqa: F401
from providers import base
from providers.base import ProviderError


class _Fixture(unittest.TestCase):
    def setUp(self):
        self._orig = (base._urlopen_json, base._curl_json, base._tun0_alive, base.TRANSPORT_HINT)
        fd, self.hint = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        os.unlink(self.hint)
        base.TRANSPORT_HINT = self.hint
        base.reset_transport_for_tests()
        self.calls = []
        self.tun0 = True
        base._tun0_alive = lambda: self.tun0

    def tearDown(self):
        base._urlopen_json, base._curl_json, base._tun0_alive, base.TRANSPORT_HINT = self._orig
        base.reset_transport_for_tests()
        if os.path.exists(self.hint):
            os.unlink(self.hint)

    def _direct(self, outcome):
        def f(req, host_label, timeout):
            self.calls.append("direct")
            if isinstance(outcome, Exception):
                raise outcome
            return outcome
        base._urlopen_json = f

    def _tun0(self, outcome):
        def f(url, headers, form_fields, host_label, timeout):
            self.calls.append("tun0")
            if isinstance(outcome, Exception):
                raise outcome
            return outcome
        base._curl_json = f


UNSENT = ProviderError("Нет связи (connect)", network=True, unsent=True)
READ_TIMEOUT = ProviderError("Нет связи (read timed out)", network=True, unsent=False)


class TestTransport(_Fixture):
    def test_direct_ok_no_fallback(self):
        self._direct({"ok": 1}); self._tun0({"via": "tun0"})
        self.assertEqual(base.http_get_json("https://x/api", host_label="x"), {"ok": 1})
        self.assertEqual(self.calls, ["direct"])
        self.assertEqual(base.preferred_transport(), "direct")

    def test_direct_blocked_falls_to_tun0_and_remembers(self):
        self._direct(UNSENT); self._tun0({"via": "tun0"})
        self.assertEqual(base.http_get_json("https://x/api", host_label="x"), {"via": "tun0"})
        self.assertEqual(self.calls, ["direct", "tun0"])
        self.assertEqual(base.preferred_transport(), "tun0")
        self.assertTrue(os.path.exists(self.hint), "подсказка для следующего процесса записана")
        # новый «процесс» читает подсказку и идёт через tun0 сразу
        base.reset_transport_for_tests()
        self.calls.clear()
        base.http_get_json("https://x/api", host_label="x")
        self.assertEqual(self.calls, ["tun0"])

    def test_mutating_read_timeout_never_retried(self):
        self._direct(READ_TIMEOUT); self._tun0({"bought": True})
        with self.assertRaises(ProviderError) as e:
            base.http_get_json("https://x/api/buy", host_label="x", mutating=True)
        self.assertTrue(e.exception.network)
        self.assertEqual(self.calls, ["direct"], "деньги: ответ мог потеряться — повтора нет")

    def test_mutating_unsent_may_retry_via_tun0(self):
        self._direct(UNSENT); self._tun0({"bought": True})
        self.assertEqual(base.http_get_json("https://x/api/buy", host_label="x", mutating=True), {"bought": True})
        self.assertEqual(self.calls, ["direct", "tun0"])

    def test_read_timeout_nonmutating_retries(self):
        self._direct(READ_TIMEOUT); self._tun0({"list": []})
        self.assertEqual(base.http_get_json("https://x/api", host_label="x"), {"list": []})
        self.assertEqual(self.calls, ["direct", "tun0"])

    def test_no_tun0_no_fallback(self):
        self.tun0 = False
        self._direct(UNSENT); self._tun0({"via": "tun0"})
        with self.assertRaises(ProviderError):
            base.http_get_json("https://x/api", host_label="x")
        self.assertEqual(self.calls, ["direct"])

    def test_preferred_tun0_but_dead_goes_direct_and_switches_back(self):
        base.set_transport("tun0", persist=False)
        self.tun0 = False
        self._direct({"ok": 1}); self._tun0({"via": "tun0"})
        self.assertEqual(base.http_get_json("https://x/api", host_label="x"), {"ok": 1})
        self.assertEqual(self.calls, ["direct"])
        self.assertEqual(base.preferred_transport(), "direct")

    def test_http_error_is_not_network_no_fallback(self):
        self._direct(ProviderError("x: API-ключ не принят (HTTP 403)", code=403)); self._tun0({"via": "tun0"})
        with self.assertRaises(ProviderError) as e:
            base.http_get_json("https://x/api", host_label="x")
        self.assertEqual(e.exception.code, 403)
        self.assertEqual(self.calls, ["direct"])

    def test_post_form_goes_through_same_transport(self):
        self._direct(UNSENT); self._tun0({"renewed": True})
        r = base.http_post_form("https://x/api/renew/", {"proxies": ["1"], "period": 7},
                                headers={"API-KEY": "k"}, host_label="x", mutating=True)
        self.assertEqual(r, {"renewed": True})
        self.assertEqual(self.calls, ["direct", "tun0"])


class TestUrlopenClassification(unittest.TestCase):
    """URLError (до ответа) -> unsent=True; сырой таймаут чтения -> unsent=False; HTTPError -> код."""

    def _run(self, exc):
        import urllib.request
        orig = urllib.request.urlopen

        def boom(req, timeout=None):
            raise exc
        urllib.request.urlopen = boom
        try:
            req = urllib.request.Request("https://x/")
            with self.assertRaises(ProviderError) as e:
                base._urlopen_json(req, "x", 5)
            return e.exception
        finally:
            urllib.request.urlopen = orig

    def test_urlerror_is_unsent(self):
        e = self._run(urllib.error.URLError(ConnectionResetError(104, "reset")))
        self.assertTrue(e.network and e.unsent)

    def test_read_timeout_not_unsent(self):
        e = self._run(TimeoutError("The read operation timed out"))
        self.assertTrue(e.network and not e.unsent)

    def test_http_error_code(self):
        import io
        err = urllib.error.HTTPError("https://x/", 403, "Forbidden", {}, io.BytesIO(b'{"detail":"bad key"}'))
        e = self._run(err)
        self.assertEqual(e.code, 403)
        self.assertFalse(e.network)
        self.assertIn("API-ключ не принят", str(e))


class TestCurlParsing(unittest.TestCase):
    """_curl_json: разбор http_code, коды curl -> unsent."""

    def setUp(self):
        self._orig = base.subprocess.run

    def tearDown(self):
        base.subprocess.run = self._orig

    def _fake(self, rc, stdout):
        class P:
            returncode = rc
        P.stdout = stdout
        base.subprocess.run = lambda *a, **k: P()

    def test_ok(self):
        self._fake(0, '{"balance":"1"}\n__HTTP__200')
        self.assertEqual(base._curl_json("https://x/", None, None, "x", 5), {"balance": "1"})

    def test_http_403(self):
        self._fake(0, '{"detail":"nope"}\n__HTTP__403')
        with self.assertRaises(ProviderError) as e:
            base._curl_json("https://x/", None, None, "x", 5)
        self.assertEqual(e.exception.code, 403)

    def test_curl_connect_fail_unsent(self):
        self._fake(7, "")
        with self.assertRaises(ProviderError) as e:
            base._curl_json("https://x/", None, None, "x", 5)
        self.assertTrue(e.exception.network and e.exception.unsent)

    def test_curl_timeout_not_unsent(self):
        self._fake(28, "")
        with self.assertRaises(ProviderError) as e:
            base._curl_json("https://x/", None, None, "x", 5)
        self.assertTrue(e.exception.network and not e.exception.unsent)


if __name__ == "__main__":
    unittest.main(verbosity=2)
