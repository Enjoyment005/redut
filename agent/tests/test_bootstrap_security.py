# -*- coding: utf-8 -*-
"""A19 regressions for bootstrap secret staging and dry-run output."""
import contextlib
import io
import os
import pathlib
import stat
import sys
import types
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
INSTALL = str(ROOT / "install")
if INSTALL not in sys.path:
    sys.path.insert(0, INSTALL)

import bootstrap  # noqa: E402
import profiles  # noqa: E402


class _Handle:
    def __init__(self, owner, path):
        self.owner = owner
        self.path = path
        self.item = owner.files[path]

    def chmod(self, mode):
        self.item["mode"] = stat.S_IFREG | mode

    def stat(self):
        return types.SimpleNamespace(st_mode=self.item["mode"], st_uid=0)

    def write(self, data):
        self.owner.mode_at_first_write = stat.S_IMODE(self.item["mode"])
        self.item["data"] += data

    def flush(self):
        pass

    def close(self):
        pass


class _SFTP:
    def __init__(self):
        self.files = {}
        self.mode_at_first_write = None

    def open(self, path, mode):
        if mode != "wx":
            raise AssertionError("bootstrap secret must use exclusive create")
        if path in self.files:
            raise FileExistsError(path)
        self.files[path] = {"mode": stat.S_IFREG | 0o644, "data": ""}
        return _Handle(self, path)

    def lstat(self, path):
        item = self.files[path]
        return types.SimpleNamespace(st_mode=item["mode"], st_uid=0)

    def remove(self, path):
        self.files.pop(path, None)


class TestBootstrapSecretSafety(unittest.TestCase):
    def test_mode_is_private_before_first_params_secret_byte(self):
        sftp = _SFTP()
        bootstrap._write_secret_staging(sftp, "/tmp/params", "PASS=sentinel")
        self.assertEqual(sftp.mode_at_first_write, 0o600)
        self.assertEqual(sftp.files["/tmp/params"]["data"], "PASS=sentinel")

    def test_dry_run_never_prints_profile_or_cli_secrets(self):
        # Keep this regression independent of private profiles.local.json in
        # the canonical operator tree.
        p = {
            "name": "node1", "host": "192.0.2.10", "root_pw": "ROOT-SENTINEL",
            "role": "vpn-node1", "subnet": "10.8.0.0/24",
            "wg_ip": "10.8.0.1", "wg_addr": "10.8.0.1/24", "wg_port": 51820,
            "singbox_version": "1.11.7", "panel_port": 8443, "dnsmasq": False,
            "clients": [{"name": "phone1", "addr": "10.8.0.2"}],
            "upstream": {"host": "198.51.100.10", "socks": 1080,
                         "http": 8080, "user": "up-user",
                         "pass": "UPSTREAM-SENTINEL"},
            "microsocks": {"port": 1080, "user": "local-user",
                            "pass": "MICROSOCKS-SENTINEL"},
        }
        net = {"wan": "eth0", "gw": "192.0.2.1", "server_ip": "192.0.2.10"}
        connection = mock.Mock()
        output = io.StringIO()
        errors = io.StringIO()
        with mock.patch.object(bootstrap, "build", return_value=p), \
                mock.patch.object(bootstrap, "connect", return_value=connection), \
                mock.patch.object(bootstrap, "detect_net", return_value=net), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            rc = bootstrap.main([
                "--host", "192.0.2.10", "--pw", "ROOT-SENTINEL", "--dry-run"])
        transcript = output.getvalue() + errors.getvalue()
        self.assertEqual(rc, 0)
        for secret in ("ROOT-SENTINEL", "UPSTREAM-SENTINEL", "MICROSOCKS-SENTINEL"):
            self.assertNotIn(secret, transcript)
        self.assertIn("UP_PASS='<redacted>'", transcript)
        self.assertIn("MICROSOCKS_PASS='<redacted>'", transcript)


if __name__ == "__main__":
    unittest.main(verbosity=2)
