# -*- coding: utf-8 -*-
"""Isolated clean-install/reinstall acceptance for install/setup_panel.py.

The real installer is executed twice against a temporary filesystem.  Service,
cron, certificate, and network discovery side effects are replaced, while file
copying and configuration preservation remain real.
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

import _ctx  # noqa: F401


ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PANEL_SRC = os.path.join(ROOT, "panel" if os.path.isdir(os.path.join(ROOT, "panel")) else "agent")
INSTALLER = os.path.join(ROOT, "install", "setup_panel.py")


def load_installer():
    spec = importlib.util.spec_from_file_location("isolated_setup_panel", INSTALLER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestCleanInstallAndReinstall(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.installer = load_installer()
        self.installer.OPT = os.path.join(self.tmp.name, "opt", "vpn-panel")
        self.installer.ETC = os.path.join(self.tmp.name, "etc", "vpn-panel")
        self.installer.VAR = os.path.join(self.tmp.name, "var", "lib", "vpn-panel")
        self.installer.detect_net = lambda: {
            "gw": "192.0.2.1", "wan": "eth-test", "server_ip": "192.0.2.10"}
        self.installer.install_units = lambda with_panel: None
        self.installer.install_crons = lambda: None
        self.installer._panel_https_ok = lambda port, tries=6: True
        self.installer.sh = lambda cmd, check=False: "active" if "is-active" in cmd else ""

        def cert(host, regen=False):
            for name in ("panel.crt", "panel.key"):
                with open(os.path.join(self.installer.ETC, name), "w", encoding="ascii") as f:
                    f.write("test certificate artifact\n")
            return "TEST:FINGERPRINT"

        self.installer.ensure_cert = cert

    def run_installer(self, *extra):
        argv = ["setup_panel.py", "--src", PANEL_SRC] + list(extra)
        with mock.patch.object(sys, "argv", argv), \
                mock.patch.object(self.installer.os, "geteuid", create=True, return_value=0):
            self.assertEqual(self.installer.main(), 0)

    def read_json(self, path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    def test_clean_install_then_reinstall_preserves_owner_state(self):
        self.run_installer("--name", "node-a", "--port", "8443", "--dnsmasq")

        installed = self.installer.AGENT_FILES + self.installer.PANEL_FILES
        for rel in installed:
            self.assertTrue(os.path.isfile(os.path.join(self.installer.OPT, rel)), rel)
        self.assertTrue(os.path.isfile(os.path.join(self.installer.OPT, "metrics.py")))
        self.assertTrue(os.path.isfile(os.path.join(self.installer.OPT, "VERSION")))

        config_path = os.path.join(self.installer.ETC, "config.json")
        secrets_path = os.path.join(self.installer.ETC, "secrets.json")
        first = self.read_json(config_path)
        self.assertEqual(first["server"], "node-a")
        self.assertEqual(first["panel_port"], 8443)
        self.assertTrue(first["has_dnsmasq"])
        self.assertEqual(self.read_json(secrets_path), {})

        owner_blocks = {
            "money": dict(first["money"], max_spend_per_day=77),
            "countries": {"strategy": "balanced", "blacklist": ["zz"]},
            "auto_prolong": {"enabled": False, "days_before": 9, "period_days": 14},
            "update": {"auto": False, "window": "01:00-02:00", "repo": "owner/fork"},
            "stability": {"min_probes": 9, "min_days": 2, "full_probes": 20,
                          "full_days": 5},
            "learning": dict(first["learning"], owner_approved=True,
                             canary_servers=["node-a"]),
        }
        first.update(owner_blocks)
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(first, f, ensure_ascii=False)
        secrets = {"admin": {"password_hash": "sentinel"},
                   "providers": {"proxy6": "provider-secret"}}
        with open(secrets_path, "w", encoding="utf-8") as f:
            json.dump(secrets, f)

        state_path = os.path.join(self.installer.VAR, "state.db")
        ring_path = os.path.join(self.installer.VAR, "cfg", "ring-sentinel.json")
        client_path = os.path.join(self.installer.VAR, "client-sentinel.json")
        for path, payload in ((state_path, b"state-db-sentinel"),
                              (ring_path, b"ring-sentinel"),
                              (client_path, b"client-sentinel")):
            with open(path, "wb") as f:
                f.write(payload)

        installed_metrics = os.path.join(self.installer.OPT, "metrics.py")
        with open(installed_metrics, "w", encoding="utf-8") as f:
            f.write("stale installed source\n")

        self.run_installer("--name", "node-b", "--port", "9443",
                           "--subnet", "10.77.0.0/24", "--wg-port", "51999")

        second = self.read_json(config_path)
        self.assertEqual(second["server"], "node-b")
        self.assertEqual(second["role"], "vpn-node-b")
        self.assertEqual(second["panel_port"], 9443)
        self.assertEqual(second["subnet"], "10.77.0.0/24")
        self.assertEqual(second["wg_port"], 51999)
        self.assertFalse(second["has_dnsmasq"])
        for key, value in owner_blocks.items():
            self.assertEqual(second[key], value, key)
        self.assertEqual(self.read_json(secrets_path), secrets)
        for path, payload in ((state_path, b"state-db-sentinel"),
                              (ring_path, b"ring-sentinel"),
                              (client_path, b"client-sentinel")):
            with open(path, "rb") as f:
                self.assertEqual(f.read(), payload)
        with open(installed_metrics, encoding="utf-8") as installed_file, \
                open(os.path.join(PANEL_SRC, "metrics.py"), encoding="utf-8") as source_file:
            self.assertEqual(installed_file.read(), source_file.read())


if __name__ == "__main__":
    unittest.main(verbosity=2)
