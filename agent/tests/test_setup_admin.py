# -*- coding: utf-8 -*-
"""setup_admin: авторестарт панели после сброса учётки (живой случай 19.08).

Панель кэширует secrets.json в памяти (App._load_secrets): владелец сбросил вход
по SSH, панель не перезапустил — и она принимала СТАРЫЙ пароль до ручного
systemctl restart. Теперь setup_admin.py перезапускает vpn-panel сам: только на
POSIX, только для боевого /etc/vpn-panel/secrets.json и только если юнит активен;
любая ошибка systemctl не роняет скрипт — остаётся прежнее печатное напоминание.
"""
import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from unittest import mock

import _ctx  # noqa: F401  (sys.path -> panel/)
from webpanel import setup_admin


def _cp(rc=0, out=""):
    return mock.Mock(returncode=rc, stdout=out, stderr="")


class TestRestartPanel(unittest.TestCase):
    def _posix(self):
        return mock.patch.object(setup_admin.os, "name", "posix")

    def test_restarts_active_unit(self):
        calls = []

        def fake_run(args, **kw):
            calls.append(list(args))
            return _cp(0, "active\n") if "is-active" in args else _cp(0)

        with self._posix(), mock.patch.object(setup_admin.subprocess, "run",
                                              side_effect=fake_run):
            self.assertTrue(setup_admin.restart_panel(setup_admin.DEFAULT_SECRETS))
        self.assertEqual(calls, [["systemctl", "is-active", "vpn-panel"],
                                 ["systemctl", "restart", "vpn-panel"]])

    def test_skips_missing_or_stopped_unit(self):
        # is-active: "inactive" (юнит стоит), "unknown" (юнита нет) -> рестарта нет
        for out in ("inactive\n", "unknown\n", ""):
            with self._posix(), mock.patch.object(setup_admin.subprocess, "run",
                                                  return_value=_cp(4, out)) as run:
                self.assertFalse(setup_admin.restart_panel(setup_admin.DEFAULT_SECRETS))
                run.assert_called_once()

    def test_restart_failure_is_false_not_crash(self):
        with self._posix(), mock.patch.object(setup_admin.subprocess, "run",
                                              side_effect=[_cp(0, "active\n"), _cp(1)]):
            self.assertFalse(setup_admin.restart_panel(setup_admin.DEFAULT_SECRETS))

    def test_survives_oserror_and_timeout(self):
        for exc in (FileNotFoundError("нет systemctl"),
                    subprocess.TimeoutExpired(["systemctl"], 10)):
            with self._posix(), mock.patch.object(setup_admin.subprocess, "run",
                                                  side_effect=exc):
                self.assertFalse(setup_admin.restart_panel(setup_admin.DEFAULT_SECRETS))

    def test_dev_secrets_do_not_touch_live_panel(self):
        with self._posix(), mock.patch.object(setup_admin.subprocess, "run") as run:
            self.assertFalse(setup_admin.restart_panel("/tmp/.secrets.local.json"))
        run.assert_not_called()

    def test_non_posix_no_systemctl(self):
        with mock.patch.object(setup_admin.os, "name", "nt"), \
             mock.patch.object(setup_admin.subprocess, "run") as run:
            self.assertFalse(setup_admin.restart_panel(setup_admin.DEFAULT_SECRETS))
        run.assert_not_called()


class TestMainWiring(unittest.TestCase):
    """main(): рестарт зовётся ПОСЛЕ записи файла, сообщение соответствует исходу."""

    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        os.unlink(self.path)

    def tearDown(self):
        if os.path.isfile(self.path):
            os.unlink(self.path)

    def _run_main(self, restarted):
        seen = {}

        def fake_restart(path):
            seen["written"] = os.path.isfile(path)
            seen["path"] = path
            return restarted

        out = io.StringIO()
        with mock.patch.object(setup_admin, "restart_panel", side_effect=fake_restart), \
             contextlib.redirect_stdout(out):
            rc = setup_admin.main(["--secrets", self.path, "--password", "pw"])
        self.assertEqual(rc, 0)
        return seen, out.getvalue()

    def test_restart_after_write_and_success_message(self):
        seen, out = self._run_main(True)
        self.assertEqual(seen, {"written": True, "path": self.path})
        self.assertIn("vpn-panel перезапущена", out)
        with open(self.path, encoding="utf-8") as f:
            self.assertIn("admin", json.load(f))

    def test_fallback_reminder_kept(self):
        _, out = self._run_main(False)
        self.assertIn("Перезапусти vpn-panel, если работает.", out)
