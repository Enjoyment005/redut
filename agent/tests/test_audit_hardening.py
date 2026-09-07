# -*- coding: utf-8 -*-
"""Regression contracts for the v1.13.0 adversarial audit closure."""
import hashlib
import io
import json
import os
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from email.message import Message
from unittest import mock

import _ctx  # noqa: F401
import dns_probe
import pool as pool_mod
import update
from webpanel import auth, server


ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestRecoveryCodeAtomicity(unittest.TestCase):
    def test_one_code_has_exactly_one_concurrent_winner(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "secrets.json")
            code = "abcd-1234"
            digest = hashlib.sha256(code.encode()).hexdigest()
            auth.write_secrets_atomic(path, {
                "admin": {"pw": "x", "totp": "x", "recovery": [digest]},
                "proxy6": {"api_key": "sentinel"},
            })
            barrier = threading.Barrier(20)

            def consume(_index):
                barrier.wait()
                return auth.consume_recovery_code(None, path, code)

            with ThreadPoolExecutor(max_workers=20) as executor:
                results = list(executor.map(consume, range(20)))
            self.assertEqual(results.count(True), 1)
            with open(path, encoding="utf-8") as source:
                final = json.load(source)
            self.assertEqual(final["admin"]["recovery"], [""])
            self.assertEqual(final["proxy6"]["api_key"], "sentinel")


class TestSetupOwnership(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = self.tmp.name
        self.config = os.path.join(root, "config.json")
        self.secrets = os.path.join(root, "secrets.json")
        self.bootstrap = os.path.join(root, "bootstrap.json")
        with open(self.config, "w", encoding="utf-8") as target:
            json.dump({"server": "test", "db": os.path.join(root, "state.db"),
                       "ring": os.path.join(root, "ring"), "server_ip": "127.0.0.1"}, target)
        with open(self.secrets, "w", encoding="utf-8") as target:
            json.dump({}, target)
        self.secret = "ssh-only-bootstrap"
        now = time.time()
        with open(self.bootstrap, "w", encoding="utf-8") as target:
            json.dump({"version": 1, "created": now, "expires": now + 3600,
                       "used": False,
                       "secret_sha256": hashlib.sha256(self.secret.encode()).hexdigest()}, target)
        self.old_env = {name: os.environ.get(name) for name in
                        ("VPN_PANEL_CONFIG", "VPN_PANEL_SECRETS", "VPN_PANEL_BOOTSTRAP")}
        os.environ.update(VPN_PANEL_CONFIG=self.config, VPN_PANEL_SECRETS=self.secrets,
                          VPN_PANEL_BOOTSTRAP=self.bootstrap)
        self.app = server.App()

    def tearDown(self):
        self.app.pool.close()
        for name, value in self.old_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        self.tmp.cleanup()

    def test_ip_knowledge_is_not_enough_and_claim_is_single_session(self):
        self.assertIsNone(self.app.claim_setup("wrong"))
        first = self.app.claim_setup(self.secret)
        self.assertTrue(first)
        self.app.setup["pw"] = "unfinished"
        second = self.app.claim_setup(self.secret)
        self.assertTrue(second)
        self.assertNotEqual(first, second)
        self.assertFalse(self.app.setup_claim_valid(first))
        self.assertTrue(self.app.setup_claim_valid(second))
        self.assertEqual(self.app.setup, {})

    def test_expired_and_consumed_bootstrap_are_rejected(self):
        with open(self.bootstrap, "r+", encoding="utf-8") as target:
            record = json.load(target)
            record["expires"] = time.time() - 1
            target.seek(0)
            json.dump(record, target)
            target.truncate()
        self.assertIsNone(self.app.claim_setup(self.secret))
        auth.consume_bootstrap_secret(self.bootstrap)
        self.assertFalse(os.path.exists(self.bootstrap))
        self.assertIsNone(self.app.claim_setup(self.secret))


class _BodyHarness:
    def __init__(self, headers, body=b""):
        self.headers = Message()
        for name, value in headers:
            self.headers[name] = value
        self.rfile = io.BytesIO(body)
        self.close_connection = False


class TestBoundedHTTPBody(unittest.TestCase):
    def test_valid_body_is_read_exactly(self):
        handler = _BodyHarness([("Content-Length", "3")], b"abc")
        self.assertEqual(server.Handler._body(handler, limit=3), b"abc")

    def test_invalid_framing_is_rejected_before_read(self):
        cases = [
            ([("Content-Length", "-1")], 400),
            ([("Content-Length", "abc")], 400),
            ([("Content-Length", "9")], 413),
            ([("Content-Length", "1"), ("Content-Length", "1")], 400),
            ([("Transfer-Encoding", "chunked"), ("Content-Length", "0")], 400),
            ([], 411),
        ]
        for headers, status in cases:
            with self.subTest(headers=headers):
                handler = _BodyHarness(headers)
                with self.assertRaises(server.RequestBodyError) as caught:
                    server.Handler._body(handler, limit=8)
                self.assertEqual(caught.exception.status, status)
                self.assertTrue(handler.close_connection)


class TestDNSWireDeadline(unittest.TestCase):
    def test_tcp_exact_reader_accepts_split_length_prefix(self):
        sock = mock.Mock()
        sock.recv.side_effect = [b"\x00", b"\x10"]
        self.assertEqual(dns_probe._recv_exact(sock, 2, time.monotonic() + 1), b"\x00\x10")

    def test_tcp_exact_reader_has_total_deadline(self):
        sock = mock.Mock()
        sock.recv.return_value = b"x"
        with mock.patch.object(dns_probe.time, "monotonic", side_effect=[0.0, 2.0]):
            with self.assertRaises(dns_probe.DNSProbeError):
                dns_probe._recv_exact(sock, 2, 1.0)


class TestUpdateDataPlane(unittest.TestCase):
    def test_peer_identity_change_fails_even_when_count_is_equal(self):
        baseline = {"units": {}, "peers": 1, "peer_map": {"old": ("10.0.0.2/32",)},
                    "panel": False}
        with mock.patch.object(update, "_singbox_ok", return_value=(True, "")), \
                mock.patch.object(update, "_is_active", return_value=True), \
                mock.patch.object(update, "_wg_peers", return_value=1), \
                mock.patch.object(update, "_wg_peer_map",
                                  return_value={"new": ("10.0.0.2/32",)}):
            ok, why = update._verify_once({}, baseline)
        self.assertFalse(ok)
        self.assertIn("identities", why)

    def test_active_dns_generation_blocks_update_preflight(self):
        with mock.patch.object(update, "_dns_update_state",
                               return_value={"phase": "active_proxy", "rescue_unit": True,
                                             "dnsmasq": None}):
            ok, why = update.dns_update_preflight({})
        self.assertFalse(ok)
        self.assertIn("DNS Rescue", why)


class TestStaticInstallerContracts(unittest.TestCase):
    def read(self, relative):
        with open(os.path.join(ROOT, relative), encoding="utf-8") as source:
            return source.read()

    def read_layout(self, canonical, public):
        """Read a source from either the canonical or allowlisted public tree."""
        for relative in (canonical, public):
            path = os.path.join(ROOT, relative)
            if os.path.isfile(path):
                with open(path, encoding="utf-8") as source:
                    return source.read()
        self.fail("missing source in canonical/public layouts: %s, %s"
                  % (canonical, public))

    def test_watchdog_has_one_implementation_and_no_direct_network_writes(self):
        canonical = self.read("install/templates/singbox-watchdog.sh")
        legacy = self.read_layout("singbox/singbox-watchdog.sh",
                                  "node/singbox-watchdog.sh")
        self.assertEqual(canonical, legacy)
        self.assertNotIn("systemctl restart sing-box", canonical)
        self.assertNotIn("systemctl start sing-box", canonical)
        self.assertNotIn("route replace default", canonical)
        setup = self.read_layout("install/setup.sh", "setup.sh")
        self.assertNotIn("node/singbox-watchdog.sh", setup)

    def test_post_hook_only_queues_reconcile(self):
        post = self.read("install/templates/singbox-post.sh")
        self.assertIn("--on-active=2s", post)
        self.assertNotIn('[ -x "$AGENT" ] && "$AGENT" rotate', post)
        self.assertNotIn("route replace default", post)

    def test_pinned_allowlist_hashes_idna_and_restart_contract(self):
        updater = self.read("install/templates/update-ru-whitelist.sh")
        for digest in (
                "dfa4ffeec6c97a6feb7c594934d0c8b4e170fadff1d781f0de012ee383832eb9",
                "8a3814375701decd9787718fc3ae769187aa4714e2a1b8fa5d96f94ad2bd4da0",
                "149d27a8e3502b95b9a378817854c87af6417c2a9bbf0b17eb8f7affef1f3868"):
            self.assertIn(digest, updater)
        self.assertIn('label.startswith("xn--")', updater)
        self.assertNotIn("systemctl reload dnsmasq", updater)
        self.assertIn("restart_dnsmasq", updater)

    def test_cleanup_is_redut_scoped_and_preserves_host_evidence(self):
        cleanup = self.read("install/templates/server_cleanup.sh")
        for forbidden in ("> /root/.ssh/known_hosts", "journalctl --vacuum", "/tmp/*.py",
                          "/opt/telegram_ws_relay.py", "reset-failed", "dmesg -C"):
            self.assertNotIn(forbidden, cleanup)
        self.assertIn("redut-owned", cleanup)

    def test_dns_api_dispatch_is_not_duplicated(self):
        source = self.read_layout("panel/webpanel/server.py", "agent/webpanel/server.py")
        self.assertEqual(source.count('if path == "/api/dns-rescue":'), 2,
                         "expected exactly one GET and one POST dispatcher")
        self.assertEqual(source.count('out["dns_rescue"] ='), 1)
        self.assertEqual(source.count("import dns_rescue as dns_rescue_mod"), 1)

    def test_panel_service_and_server_have_resource_caps(self):
        installer = self.read("install/setup_panel.py")
        for marker in ("MemoryMax=512M", "TasksMax=64", "LimitNOFILE=4096"):
            self.assertIn(marker, installer)
        self.assertEqual(server._MAX_HTTP_WORKERS, 32)
        self.assertEqual(server.MAX_REQUEST_BODY, 64 * 1024)


if __name__ == "__main__":
    unittest.main()
