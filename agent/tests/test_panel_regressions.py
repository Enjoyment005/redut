# -*- coding: utf-8 -*-
"""Regression tests for the v1.13.2 panel review; no services or providers."""
import hashlib
import io
import json
import os
import re
import socket
import sqlite3
import tempfile
import threading
import time
import types
import unittest
from unittest import mock
from urllib.parse import urlencode

import _ctx  # noqa: F401
from webpanel import auth, server


class TestReloadSecretsSerialization(unittest.TestCase):
    def test_every_reload_holds_shared_db_lock(self):
        app = server.App.__new__(server.App)
        observed = []
        app._load_secrets = lambda: observed.append(server._DB_LOCK._is_owned())
        app.reload_secrets()
        self.assertEqual(observed, [True])


class TestLoginCredentialSnapshot(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "secrets.json")
        self.conn = sqlite3.connect(":memory:")
        self.addCleanup(self.conn.close)
        self.store = auth.AuthStore(self.conn)
        self.password = "old-password"
        self.seed = auth.totp_new_seed()
        self.old_recovery = "abcd-1234"
        self.new_recovery = "5678-90ab"
        self.now = 1_800_000_000
        self.app = types.SimpleNamespace(
            store=self.store, pool=mock.Mock(), secrets_path=self.path)
        self.app.reload_secrets = self.reload
        self.install(self.password, self.seed, self.old_recovery)
        patcher = mock.patch.object(server, "APP", self.app)
        patcher.start()
        self.addCleanup(patcher.stop)

    def install(self, password, seed, recovery):
        auth.write_admin_credentials_atomic(self.path, {"admin": {
            "pw": auth.hash_password(password, n=1024), "totp": seed,
            "recovery": [hashlib.sha256(recovery.encode()).hexdigest()],
        }}, self.store, force=True)
        self.reload()

    def reload(self):
        with open(self.path, encoding="utf-8") as source:
            self.app.secrets = json.load(source)
        self.app.admin = self.app.secrets["admin"]
        self.app.admin_epoch = auth.admin_credential_epoch(self.app.admin)

    def login(self, otp, rotate=False):
        handler = server.Handler.__new__(server.Handler)
        handler._client_ip = lambda: "127.0.0.1"
        handler._body = lambda **kwargs: urlencode(
            {"password": self.password, "otp": otp}).encode()
        handler._send = mock.Mock()
        handler._json = mock.Mock()
        handler._redirect = mock.Mock()
        verify = auth.verify_password

        def verify_then_reset(password, stored):
            result = verify(password, stored)
            if rotate:
                # Deterministic interleaving: reset and panel reload complete
                # after this request took its old credential snapshot.
                self.install("new-password", auth.totp_new_seed(), self.new_recovery)
            return result

        with mock.patch.object(auth, "verify_password", side_effect=verify_then_reset), \
                mock.patch.object(auth.time, "time", return_value=self.now):
            handler._do_login()
        return handler

    def assert_rejected(self, handler):
        handler._redirect.assert_not_called()
        self.assertEqual(handler._send.call_args.args[0], 401)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM session").fetchone()[0], 0)

    def test_old_password_and_totp_cannot_cross_reset_and_reload(self):
        otp = auth._totp_at(self.seed, self.now // auth.TOTP_STEP)
        self.assert_rejected(self.login(otp, rotate=True))

    def test_old_password_cannot_consume_recovery_from_new_epoch(self):
        self.assert_rejected(self.login(self.new_recovery, rotate=True))
        self.reload()
        self.assertEqual(auth.recovery_match(self.new_recovery,
                                            self.app.admin["recovery"]), 0)

    def test_unchanged_totp_login_succeeds(self):
        otp = auth._totp_at(self.seed, self.now // auth.TOTP_STEP)
        handler = self.login(otp)
        handler._redirect.assert_called_once()
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM session").fetchone()[0], 1)

    def test_unchanged_recovery_login_succeeds_exactly_once(self):
        original_reload = self.app.reload_secrets

        def reload_under_db_lock():
            self.assertTrue(server._DB_LOCK._is_owned())
            original_reload()

        self.app.reload_secrets = reload_under_db_lock
        self.login(self.old_recovery)._redirect.assert_called_once()
        self.conn.execute("DELETE FROM session")
        self.conn.commit()
        self.assert_rejected(self.login(self.old_recovery))


class TestEmergencyBooleanContract(unittest.TestCase):
    def call(self, body):
        handler = server.Handler.__new__(server.Handler)
        handler._body = lambda **kwargs: json.dumps(body).encode()
        handler._client_ip = lambda: "127.0.0.1"
        handler._json = mock.Mock()
        app = types.SimpleNamespace(pool=mock.Mock())
        app.pool.get_setting.return_value = "OK"
        with mock.patch.object(server, "APP", app), \
                mock.patch.object(server, "_run_agent", return_value=(0, "")) as run:
            handler._api_post("/api/emergency")
        return handler, run

    def test_non_boolean_never_changes_egress(self):
        for body in ({}, {"on": "false"}, {"on": "true"}, {"on": 0},
                     {"on": 1}, {"on": None}, {"on": []}, {"on": {}}):
            with self.subTest(body=body):
                handler, run = self.call(body)
                run.assert_not_called()
                self.assertEqual(handler._json.call_args.args[0], 400)

    def test_explicit_booleans_preserve_requested_direction(self):
        for on in (False, True):
            with self.subTest(on=on):
                handler, run = self.call({"on": on})
                run.assert_called_once_with(["emergency", "on" if on else "off"])
                self.assertEqual(handler._json.call_args.args[0], 200)


class _MemorySocket:
    """Exercise the real HTTP parser and keep-alive loop without a listener."""
    def __init__(self, raw):
        self.input = io.BytesIO(raw)
        self.output = bytearray()

    def makefile(self, *args, **kwargs):
        return self.input

    def sendall(self, data):
        self.output.extend(data)


class TestPostKeepAliveFraming(unittest.TestCase):
    def exchange(self, requests, app):
        sock = _MemorySocket(requests)
        with mock.patch.object(server, "APP", app):
            server.Handler(sock, ("127.0.0.1", 12345), mock.Mock())
        return [int(status) for status in
                re.findall(rb"HTTP/1\.1 (\d{3}) ", bytes(sock.output))]

    def test_banned_login_drains_body_before_next_request(self):
        app = types.SimpleNamespace(provisioned=True, store=mock.Mock())
        app.store.is_banned.return_value = 60
        reply = self.exchange(
            b"POST /login HTTP/1.1\r\nHost: test\r\nContent-Length: 3\r\n\r\nx=y"
            b"GET /healthz HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n", app)
        self.assertEqual(reply, [429, 200])

    def test_unauthorized_post_drains_body_before_next_request(self):
        app = types.SimpleNamespace(store=mock.Mock(), provisioned=True)
        app.store.get_session.return_value = None
        reply = self.exchange(
            b"POST /api/emergency HTTP/1.1\r\nHost: test\r\nContent-Length: 2\r\n\r\n{}"
            b"GET /healthz HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n", app)
        self.assertEqual(reply, [401, 200])

    def test_each_post_has_its_own_reusable_body(self):
        app = types.SimpleNamespace(store=mock.Mock(), pool=mock.Mock(), provisioned=True)
        app.store.get_session.return_value = {"csrf": "token"}
        app.pool.get_setting.return_value = "OK"
        requests = b""
        for body in (b'{"on":true}', b'{"on":false}'):
            requests += (b"POST /api/emergency HTTP/1.1\r\nHost: test\r\n"
                         b"X-CSRF-Token: token\r\nContent-Length: "
                         + str(len(body)).encode() + b"\r\n\r\n" + body)
        requests += b"GET /healthz HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"
        with mock.patch.object(server, "_run_agent", return_value=(0, "")) as run:
            self.assertEqual(self.exchange(requests, app), [200, 200, 200])
        self.assertEqual(run.call_args_list, [mock.call(["emergency", "on"]),
                                             mock.call(["emergency", "off"])])

    def test_login_still_enforces_its_smaller_body_limit(self):
        app = types.SimpleNamespace(provisioned=True, store=mock.Mock())
        app.store.is_banned.return_value = 0
        reply = self.exchange(
            b"POST /login HTTP/1.1\r\nHost: test\r\nContent-Length: 8193\r\n\r\n"
            + b"x" * 8193, app)
        self.assertEqual(reply, [413])

    def test_duplicate_transfer_encoding_cannot_smuggle_a_next_request(self):
        app = types.SimpleNamespace(provisioned=True, store=mock.Mock())
        app.store.is_banned.return_value = 0
        reply = self.exchange(
            b"POST /login HTTP/1.1\r\nHost: test\r\n"
            b"Transfer-Encoding:\r\nTransfer-Encoding: chunked\r\n"
            b"Content-Length: 0\r\n\r\n"
            b"4\r\nx=y!\r\n0\r\n\r\n"
            b"GET /healthz HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
            app)
        self.assertEqual(reply, [400])

    def test_non_digit_content_length_is_rejected_and_connection_closed(self):
        app = types.SimpleNamespace(provisioned=True, store=mock.Mock())
        app.store.is_banned.return_value = 0
        for value in (b"+0", b"0_0"):
            with self.subTest(value=value):
                reply = self.exchange(
                    b"POST /login HTTP/1.1\r\nHost: test\r\nContent-Length: "
                    + value + b"\r\n\r\n"
                    b"GET /healthz HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
                    app)
                self.assertEqual(reply, [400])

    def test_absolute_request_deadline_stops_byte_trickle(self):
        server_socket, client_socket = socket.socketpair()
        errors = []

        def serve():
            try:
                with mock.patch.object(server, "_CONN_TIMEOUT", 0.06):
                    server.Handler(server_socket, ("127.0.0.1", 12345), mock.Mock())
            except Exception as error:  # pragma: no cover - diagnostic only
                errors.append(error)

        worker = threading.Thread(target=serve, daemon=True)
        started = time.monotonic()
        worker.start()
        try:
            # Every pause is shorter than the old idle timeout, while the total
            # request-line read exceeds the new absolute deadline.
            for byte in b"POST /login HTTP/1.1\r\n":
                try:
                    client_socket.sendall(bytes([byte]))
                except OSError:
                    break
                time.sleep(0.02)
            worker.join(0.5)
            self.assertFalse(worker.is_alive())
            self.assertLess(time.monotonic() - started, 0.5)
            self.assertTrue(all(isinstance(error, OSError) for error in errors), errors)
        finally:
            client_socket.close()
            server_socket.close()


if __name__ == "__main__":
    unittest.main()
