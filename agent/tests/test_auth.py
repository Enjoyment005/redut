# -*- coding: utf-8 -*-
"""Аутентификация панели: TOTP (вектор RFC 6238), scrypt, recovery, антибрут, сессии."""
import sqlite3
import unittest

import _ctx  # noqa: F401  (sys.path -> panel/)
from webpanel import auth


class TestTOTP(unittest.TestCase):
    def test_rfc6238_vector(self):
        # RFC 6238: seed ASCII "12345678901234567890" (SHA1), T=59 -> 6 знаков 287082
        seed = auth.base64.b32encode(b"12345678901234567890").decode()
        self.assertEqual(auth._totp_at(seed, 59 // auth.TOTP_STEP), "287082")

    def test_verify_window(self):
        seed = auth.totp_new_seed()
        now = 1_000_000
        good = auth._totp_at(seed, now // auth.TOTP_STEP)
        self.assertTrue(auth.totp_verify(seed, good, now=now))
        # код предыдущего шага принимается (окно ±1: уехавшие часы)
        prev = auth._totp_at(seed, now // auth.TOTP_STEP - 1)
        self.assertTrue(auth.totp_verify(seed, prev, now=now))
        # код за 2 шага назад — уже нет
        old = auth._totp_at(seed, now // auth.TOTP_STEP - 2)
        self.assertFalse(auth.totp_verify(seed, old, now=now))

    def test_verify_rejects_garbage(self):
        seed = auth.totp_new_seed()
        self.assertFalse(auth.totp_verify(seed, "abc"))
        self.assertFalse(auth.totp_verify(seed, ""))
        self.assertFalse(auth.totp_verify(seed, "000000"))

    def test_uri(self):
        seed = auth.totp_new_seed()
        uri = auth.totp_uri(seed, "node1")
        self.assertIn("otpauth://totp/", uri)
        self.assertIn(seed, uri)


class TestPassword(unittest.TestCase):
    def test_roundtrip(self):
        # быстрые параметры для теста
        h = auth.hash_password("s3cret!\"'", n=2 ** 10)
        self.assertTrue(auth.verify_password("s3cret!\"'", h))
        self.assertFalse(auth.verify_password("wrong", h))

    def test_unique_salt(self):
        self.assertNotEqual(auth.hash_password("x", n=2 ** 10), auth.hash_password("x", n=2 ** 10))


class TestRecovery(unittest.TestCase):
    def test_gen_and_match(self):
        plain, hashes = auth.gen_recovery_codes(10)
        self.assertEqual(len(plain), 10)
        self.assertEqual(auth.recovery_match(plain[3], hashes), 3)
        self.assertEqual(auth.recovery_match("nope", hashes), -1)

    def test_consumed_code_blanked(self):
        import json, os, tempfile
        plain, hashes = auth.gen_recovery_codes(3)
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        with open(path, "w") as f:
            json.dump({"admin": {"recovery": hashes}}, f)
        try:
            self.assertTrue(auth.consume_recovery_code(None, path, plain[1]))
            # повторно тот же код уже не проходит (одноразовость)
            self.assertFalse(auth.consume_recovery_code(None, path, plain[1]))
            self.assertTrue(auth.consume_recovery_code(None, path, plain[0]))
        finally:
            os.unlink(path)


class TestAuthStore(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.store = auth.AuthStore(self.conn)

    def test_session_lifecycle(self):
        tok, csrf = self.store.create_session("1.2.3.4", now=1000)
        s = self.store.get_session(tok, now=1001)
        self.assertEqual(s["csrf"], csrf)
        self.assertEqual(s["src_ip"], "1.2.3.4")
        # истёкшая сессия удаляется
        self.assertIsNone(self.store.get_session(tok, now=1000 + auth.SESSION_TTL + 1))
        self.assertIsNone(self.store.get_session(tok, now=1002))

    def test_logout(self):
        tok, _ = self.store.create_session("1.2.3.4", now=1000)
        self.store.destroy_session(tok)
        self.assertIsNone(self.store.get_session(tok, now=1001))

    def test_bruteforce_ban(self):
        ip = "9.9.9.9"
        for i in range(auth.BRUTE_MAX_FAILS - 1):
            fails, ban = self.store.record_fail(ip, now=100 + i)
            self.assertEqual(ban, 0)
            self.assertEqual(self.store.is_banned(ip, now=100 + i), 0)
        fails, ban = self.store.record_fail(ip, now=200)
        self.assertEqual(ban, auth.BRUTE_BASE_BAN, "порог -> бан")
        self.assertGreater(self.store.is_banned(ip, now=201), 0)
        # после бана — снова свободно
        self.assertEqual(self.store.is_banned(ip, now=200 + auth.BRUTE_BASE_BAN + 1), 0)

    def test_success_resets_fails(self):
        ip = "8.8.8.8"
        self.store.record_fail(ip, now=100)
        self.store.record_success(ip)
        self.assertEqual(self.store.is_banned(ip, now=101), 0)
        # счётчик обнулён: снова нужен полный набор неудач до бана
        for i in range(auth.BRUTE_MAX_FAILS - 1):
            _, ban = self.store.record_fail(ip, now=110 + i)
            self.assertEqual(ban, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
