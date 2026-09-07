# -*- coding: utf-8 -*-
"""Regression checks for route, service and credential-file boundaries.

All system commands are mocked; files are created only in temporary folders.
"""
import json
import os
import stat
import tempfile
import unittest
from unittest import mock

import _ctx
import apply as apply_mod


class TestApplyRuntimeSafety(unittest.TestCase):
    def test_failed_route_install_keeps_old_escape_route(self):
        with mock.patch.object(apply_mod, "run_cmd", return_value=(2, "invalid gateway")) as run:
            with self.assertRaises(apply_mod.ApplyError):
                apply_mod.antiloop_replace(
                    "203.0.113.2", "203.0.113.1", "192.0.2.1", "eth0")
        self.assertEqual(run.call_count, 1, "must not delete the working route after failure")

    def test_failed_restart_cannot_pass_using_old_active_process(self):
        with mock.patch.object(apply_mod, "run_cmd", side_effect=[
                (1, "restart job failed"), (0, "active")]), mock.patch.object(apply_mod.time, "sleep"):
            self.assertFalse(apply_mod.restart_singbox())

    def test_failed_state_inspection_cannot_pass_using_active_text(self):
        with mock.patch.object(apply_mod, "run_cmd", side_effect=[
                (0, ""), (1, "active")]), mock.patch.object(apply_mod.time, "sleep"):
            self.assertFalse(apply_mod.restart_singbox())

    def test_failed_telegram_transfer_cannot_report_healthy(self):
        with mock.patch.object(apply_mod, "run_cmd", side_effect=[
                (0, "203.0.113.2"), (28, "200")]), mock.patch.object(
                    apply_mod.probe_mod, "geo_country", return_value="de"):
            result = apply_mod.verify_egress()
        self.assertFalse(result["ok"])
        self.assertEqual(result["tg_code"], "000")

    def test_failed_ip_transfer_cannot_report_healthy(self):
        with mock.patch.object(apply_mod, "run_cmd", return_value=(28, "203.0.113.2")), \
                mock.patch.object(apply_mod.probe_mod, "geo_country") as geo:
            result = apply_mod.verify_egress()
        self.assertFalse(result["ok"])
        self.assertIsNone(result["egress_ip"])
        geo.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "POSIX credential-file permissions")
    def test_candidate_credentials_are_private_under_permissive_umask(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "config.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"outbounds": [], "route": {"rules": []}}, handle)
            os.chmod(path, 0o600)
            original_umask = os.umask(0o022)
            try:
                stage = apply_mod.stage_candidate(
                    {"singbox_config": path},
                    {"host": "203.0.113.2", "user": "user", "password": "secret"},
                    {"socks_port": 1080, "http_port": None})[0]
            finally:
                os.umask(original_umask)
            self.assertEqual(stat.S_IMODE(os.stat(stage).st_mode), 0o600)

    def test_json_write_failure_cleans_partial_secret_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "config.json")
            with self.assertRaises(TypeError):
                apply_mod.dump_json_replace({"password": "secret", "bad": object()}, path)
            self.assertEqual(os.listdir(directory), [])

    def test_boot_rotation_does_not_corrupt_other_ip_addresses(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "boot.sh")
            before = ('#!/bin/bash\nUP_HOST="1.2.3.4"\n'
                      'ip route replace "$UP_HOST/32" via 11.2.3.4 dev eth0\n'
                      'ip route replace 1.2.3.40/32 via 11.2.3.4 dev eth0\n')
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(before)
            self.assertTrue(apply_mod.patch_boot_script(path, "1.2.3.4", "8.8.8.8"))
            with open(path, encoding="utf-8") as handle:
                after = handle.read()
        self.assertEqual(after, before.replace('UP_HOST="1.2.3.4"', 'UP_HOST="8.8.8.8"'))


if __name__ == "__main__":
    unittest.main()
