# -*- coding: utf-8 -*-
import json
import ipaddress
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from webpanel import clients


class TestClientMembershipSafety(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.wg_conf = os.path.join(self.tmp.name, "wg0.conf")
        self.clients_dir = os.path.join(self.tmp.name, "clients")
        self.marker = os.path.join(self.tmp.name, "wg-client-operation.json")
        with open(self.wg_conf, "w", encoding="utf-8") as handle:
            handle.write("[Interface]\nPrivateKey = server-private\n")
        self.patches = [
            mock.patch.object(clients, "WG_CONF", self.wg_conf),
            mock.patch.object(clients, "CLIENTS_DIR", self.clients_dir),
            mock.patch.object(clients, "CLIENT_OP_MARK", self.marker),
        ]
        for patcher in self.patches:
            patcher.start()
        self.cfg = {"subnet": "10.77.0.0/24", "lock": "test.lock"}

    class _DNSPool:
        def __init__(self, phase="idle", scope=None, unfinished=None,
                     exit_resume=None, boot_resume=None):
            self.state = {"phase": phase, "active_scope": scope}
            self.unfinished = unfinished or []
            self.settings = {"dns_exit_resume": exit_resume,
                             "dns_boot_resume": boot_resume}

        def dns_state(self):
            return dict(self.state)

        def unfinished_dns_operations(self):
            return list(self.unfinished)

        def get_setting(self, key):
            return self.settings.get(key)

    def tearDown(self):
        for patcher in reversed(self.patches):
            patcher.stop()
        self.tmp.cleanup()

    def test_command_timeout_is_a_client_error(self):
        with mock.patch.object(clients.subprocess, "run",
                               side_effect=subprocess.TimeoutExpired("wg", 20)):
            with self.assertRaises(clients.ClientError):
                clients._run(["wg", "show"])

    def test_public_mutation_takes_the_common_lock(self):
        lock = mock.MagicMock()
        lock.__enter__.return_value = lock
        with mock.patch.object(clients.apply_mod, "Flock", return_value=lock) as flock, \
             mock.patch.object(clients, "reconcile_client_operation",
                               return_value={"ok": True}):
            with self.assertRaises(clients.ClientError):
                clients.add_client(self.cfg, "bad name")
        flock.assert_called_once_with("test.lock")
        lock.__enter__.assert_called_once()

    def test_crashed_add_rolls_forward_without_new_crud_request(self):
        desired = ("[Interface]\nPrivateKey = server-private\n\n[Peer]\n"
                   "# phone\nPublicKey = pub\nPresharedKey = psk\n"
                   "AllowedIPs = 10.77.0.9/32\n")
        clients._write_client_operation({
            "kind": "add", "name": "phone", "pubkey": "pub",
            "psk": "psk", "address": "10.77.0.9",
            "wg_config": desired, "client_conf": "[Interface]\nPrivateKey = priv\n"})
        with mock.patch.object(clients, "_set_live_peer") as live, \
             mock.patch.object(clients, "_live_peer_matches", return_value=True):
            result = clients.reconcile_client_operation(self.cfg, _locked=True)
        self.assertTrue(result["ok"])
        live.assert_called_once_with("pub", "psk", "10.77.0.9")
        self.assertFalse(os.path.exists(self.marker))
        with open(self.wg_conf, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), desired)
        self.assertTrue(os.path.isfile(os.path.join(self.clients_dir, "phone.conf")))

    def test_crashed_delete_rolls_forward_live_revoke(self):
        desired = "[Interface]\nPrivateKey = server-private\n"
        os.makedirs(self.clients_dir)
        with open(os.path.join(self.clients_dir, "phone.conf"), "w",
                  encoding="utf-8") as handle:
            handle.write("secret")
        clients._write_client_operation({
            "kind": "delete", "name": "phone", "pubkey": "pub",
            "address": "10.77.0.9", "wg_config": desired})
        with mock.patch.object(clients, "_run", return_value=""), \
             mock.patch.object(clients, "_live_peer_absent", return_value=True):
            result = clients.reconcile_client_operation(self.cfg, _locked=True)
        self.assertTrue(result["ok"])
        self.assertFalse(os.path.exists(self.marker))
        self.assertFalse(os.path.exists(os.path.join(self.clients_dir, "phone.conf")))

    def test_delete_timeout_rolls_back_and_clears_completed_marker(self):
        original = ("[Interface]\nPrivateKey = server-private\n\n[Peer]\n"
                    "# phone\nPublicKey = pub\nPresharedKey = psk\n"
                    "AllowedIPs = 10.77.0.9/32\n")
        with open(self.wg_conf, "w", encoding="utf-8") as handle:
            handle.write(original)
        params = {"text": original, "net": None, "wg_ip": "10.77.0.1"}
        with mock.patch.object(clients, "server_params", return_value=params), \
             mock.patch.object(clients, "_run",
                               side_effect=clients.ClientError("timeout")), \
             mock.patch.object(clients, "_set_live_peer_allowed_ips"), \
             mock.patch.object(clients, "_live_peer_allowed_ips_match", return_value=True):
            with self.assertRaises(clients.ClientError):
                clients.delete_client(self.cfg, "phone", _locked=True)
        with open(self.wg_conf, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), original)
        self.assertFalse(os.path.exists(self.marker))

    def test_active_or_unfinished_dns_rescue_blocks_membership_mutation(self):
        states = [
            self._DNSPool(phase="active_isolated", scope="peer:10.77.0.9"),
            self._DNSPool(unfinished=[{"id": 1}]),
            self._DNSPool(exit_resume="opaque"),
            self._DNSPool(boot_resume="opaque"),
        ]
        for dns_pool in states:
            with self.subTest(state=dns_pool.state, settings=dns_pool.settings), \
                 self.assertRaises(clients.ClientError), \
                 mock.patch.object(clients, "server_params") as params:
                clients.add_client(
                    self.cfg, "phone", _locked=True, dns_pool=dns_pool)
            params.assert_not_called()

    def test_proven_target_is_not_rolled_back_when_marker_clear_fails(self):
        desired = ("[Interface]\nPrivateKey = server-private\n\n[Peer]\n"
                   "# phone\nPublicKey = pub\nPresharedKey = psk\n"
                   "AllowedIPs = 10.77.0.9/32\n")
        clients._write_client_operation({
            "kind": "add", "name": "phone", "pubkey": "pub",
            "psk": "psk", "address": "10.77.0.9",
            "wg_config": desired,
            "rollback_wg_config": "[Interface]\nPrivateKey = server-private\n",
            "client_conf": "[Interface]\nPrivateKey = priv\n"})
        with mock.patch.object(clients, "_set_live_peer"), \
             mock.patch.object(clients, "_live_peer_matches", return_value=True), \
             mock.patch.object(clients, "_clear_client_operation",
                               side_effect=OSError("read-only")):
            result = clients.reconcile_client_operation(
                self.cfg, _locked=True, dns_pool=self._DNSPool())
        self.assertTrue(result["ok"])
        self.assertTrue(result["recovery_pending"])
        self.assertTrue(os.path.exists(self.marker))
        with open(self.wg_conf, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), desired)

    def test_pending_client_saga_can_finish_after_dns_resume_teardown(self):
        desired = ("[Interface]\nPrivateKey = server-private\n\n[Peer]\n"
                   "# phone\nPublicKey = pub\nPresharedKey = psk\n"
                   "AllowedIPs = 10.77.0.9/32\n")
        clients._write_client_operation({
            "kind": "add", "name": "phone", "pubkey": "pub",
            "psk": "psk", "address": "10.77.0.9",
            "wg_config": desired,
            "rollback_wg_config": "[Interface]\nPrivateKey = server-private\n",
            "client_conf": "[Interface]\nPrivateKey = priv\n"})
        dns_pool = self._DNSPool(phase="failed", exit_resume="opaque")
        with mock.patch.object(clients, "_set_live_peer"), \
             mock.patch.object(clients, "_live_peer_matches", return_value=True):
            result = clients.reconcile_client_operation(
                self.cfg, _locked=True, dns_pool=dns_pool)
        self.assertTrue(result["ok"])
        self.assertFalse(os.path.exists(self.marker))

    def test_delete_refuses_missing_allowed_ips_before_journal(self):
        for lines in (("",), ()):
            text = ("[Interface]\nPrivateKey = server-private\n\n[Peer]\n"
                    "# phone\nPublicKey = pub\nPresharedKey = psk\n"
                    + "".join("AllowedIPs = %s\n" % item for item in lines))
            with self.subTest(allowed=lines), \
                 mock.patch.object(clients, "server_params", return_value={
                     "text": text, "net": None, "wg_ip": "10.77.0.1"}), \
                 mock.patch.object(clients, "_write_client_operation") as journal, \
                 self.assertRaises(clients.ClientError):
                clients.delete_client(
                    self.cfg, "phone", _locked=True,
                    dns_pool=self._DNSPool())
            journal.assert_not_called()

    def test_legacy_multi_allowed_ips_can_be_revoked_and_rolled_back_exactly(self):
        original = ("[Interface]\nPrivateKey = server-private\n\n[Peer]\n"
                    "# phone\nPublicKey = pub\nPresharedKey = psk\n"
                    "AllowedIPs = 10.77.0.9/32, fd00::9/128\n")
        params = {"text": original, "net": None, "wg_ip": "10.77.0.1"}
        commands = []

        def run(args, inp=None, timeout=20):
            commands.append(args)
            if args == ["wg", "show", "wg0", "allowed-ips"]:
                return "" if len(commands) == 2 else "pub\t10.77.0.9/32,fd00::9/128\n"
            if args[:4] == ["wg", "set", "wg0", "peer"] and args[-1] == "remove":
                raise clients.ClientError("synthetic delete timeout")
            return ""

        with mock.patch.object(clients, "server_params", return_value=params), \
             mock.patch.object(clients, "_run", side_effect=run):
            with self.assertRaises(clients.ClientError):
                clients.delete_client(
                    self.cfg, "phone", _locked=True, dns_pool=self._DNSPool())
        self.assertFalse(os.path.exists(self.marker))
        with open(self.wg_conf, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), original)
        restore = next(command for command in commands
                       if command[:4] == ["wg", "set", "wg0", "peer"]
                       and "allowed-ips" in command)
        self.assertEqual(restore[-1], "10.77.0.9/32,fd00::9/128")

    def test_remove_peer_matches_public_key_exactly(self):
        text = ("[Interface]\nPrivateKey = key\n\n[Peer]\n# one\nPublicKey = pub\n"
                "AllowedIPs = 10.77.0.2/32\n\n[Peer]\n# two\nPublicKey = pub-extra\n"
                "AllowedIPs = 10.77.0.3/32\n")
        result = clients._remove_peer_block_text(text, "pub")
        self.assertNotIn("PublicKey = pub\n", result)
        self.assertIn("PublicKey = pub-extra", result)

    def test_remove_peer_public_key_value_is_case_sensitive(self):
        upper = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
        lower = "aAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
        text = ("[Interface]\nPrivateKey = key\n\n[Peer]\n# upper\nPublicKey = %s\n"
                "AllowedIPs = 10.77.0.2/32\n\n[Peer]\n# lower\nPublicKey = %s\n"
                "AllowedIPs = 10.77.0.3/32\n" % (upper, lower))
        result = clients._remove_peer_block_text(text, upper)
        self.assertNotIn("PublicKey = " + upper, result)
        self.assertIn("PublicKey = " + lower, result)

    def test_legacy_delete_marker_address_must_stay_inside_vpn_subnet(self):
        clients._write_client_operation({
            "kind": "delete", "name": "phone", "pubkey": "pub",
            "address": "192.0.2.10",
            "wg_config": "[Interface]\nPrivateKey = server-private\n"})
        with self.assertRaises(clients.ClientError):
            clients.reconcile_client_operation(self.cfg, _locked=True)

    def test_unnamed_legacy_peer_is_revoked_by_exact_public_key(self):
        pubkey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
        original = ("[Interface]\nPrivateKey = server-private\n\n[Peer]\n"
                    "PublicKey = %s\nAllowedIPs = 10.77.0.9/32, fd00::9/128\n"
                    % pubkey)
        with open(self.wg_conf, "w", encoding="utf-8") as handle:
            handle.write(original)
        params = {"text": original, "net": None, "wg_ip": "10.77.0.1"}
        with mock.patch.object(clients, "server_params", return_value=params), \
             mock.patch.object(clients, "_run", return_value=""), \
             mock.patch.object(clients, "_live_peer_absent", return_value=True):
            result = clients.delete_client(
                self.cfg, "peer-10-77-0-9", pubkey=pubkey,
                _locked=True, dns_pool=self._DNSPool())
        self.assertEqual(result["pubkey"], pubkey)
        self.assertTrue(result["removed_peer"])
        with open(self.wg_conf, encoding="utf-8") as handle:
            self.assertNotIn(pubkey, handle.read())

    def test_duplicate_names_require_and_honor_exact_public_key(self):
        first = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
        second = "aAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
        original = ("[Interface]\nPrivateKey = server-private\n\n"
                    "[Peer]\n# phone\nPublicKey = %s\nAllowedIPs = 10.77.0.2/32\n\n"
                    "[Peer]\n# phone\nPublicKey = %s\nAllowedIPs = 10.77.0.3/32\n"
                    % (first, second))
        with open(self.wg_conf, "w", encoding="utf-8") as handle:
            handle.write(original)
        params = {"text": original, "net": None, "wg_ip": "10.77.0.1"}
        with mock.patch.object(clients, "server_params", return_value=params), \
             self.assertRaises(clients.ClientError):
            clients.delete_client(
                self.cfg, "phone", _locked=True, dns_pool=self._DNSPool())
        with mock.patch.object(clients, "server_params", return_value=params), \
             mock.patch.object(clients, "_run", return_value=""), \
             mock.patch.object(clients, "_live_peer_absent", return_value=True):
            clients.delete_client(
                self.cfg, "phone", pubkey=second,
                _locked=True, dns_pool=self._DNSPool())
        with open(self.wg_conf, encoding="utf-8") as handle:
            final = handle.read()
        self.assertIn(first, final)
        self.assertNotIn(second, final)

    def test_ipv6_first_legacy_inventory_finds_exact_saved_profile(self):
        os.makedirs(self.clients_dir)
        with open(os.path.join(self.clients_dir, "phone.conf"), "w",
                  encoding="utf-8") as handle:
            handle.write("[Interface]\nAddress = 10.77.0.9/32\n")
        with open(self.wg_conf, "w", encoding="utf-8") as handle:
            handle.write("[Interface]\nPrivateKey = server-private\n\n[Peer]\n"
                         "PublicKey = pub\n"
                         "AllowedIPs = fd00::9/128, 10.77.0.9/32\n")
        with mock.patch.object(clients, "_wg_dump", return_value={}), \
             mock.patch.object(clients, "_server_pubkey", return_value="server-public"):
            result = clients.client_inventory(self.cfg)
        row = result["clients"][0]
        self.assertEqual((row["name"], row["ip"], row["has_conf"]),
                         ("phone", "10.77.0.9", True))
        self.assertTrue(row["unsupported"])

    def test_live_peer_match_requires_exact_single_allowed_ip(self):
        with mock.patch.object(
                clients, "_run",
                return_value="pub\t10.77.0.9/32,10.77.0.10/32\n"):
            self.assertFalse(clients._live_peer_matches("pub", "10.77.0.9"))

    def test_add_refuses_ambiguous_or_overlapping_existing_inventory(self):
        bodies = [
            ("[Peer]\nPublicKey = old-a\n"
             "AllowedIPs = 10.77.0.9/32, 10.77.0.10/32\n"),
            ("[Peer]\nPublicKey = old-a\nAllowedIPs = 10.77.0.9/32\n"
             "AllowedIPs = 10.77.0.10/32\n"),
            ("[Peer]\nPublicKey = old-a\nAllowedIPs = 10.77.0.9/32\n"
             "[Peer]\nPublicKey = old-b\nAllowedIPs = 10.77.0.9/32\n"),
        ]
        for body in bodies:
            params = {
                "text": "[Interface]\nPrivateKey = server-private\n" + body,
                "net": ipaddress.ip_network("10.77.0.0/24"),
                "wg_ip": "10.77.0.1"}
            with self.subTest(body=body), \
                 mock.patch.object(clients, "server_params",
                                   return_value=params), \
                 mock.patch.object(clients, "_run") as command, \
                 mock.patch.object(clients,
                                   "_write_client_operation") as journal, \
                 self.assertRaises(clients.ClientError):
                clients.add_client(
                    self.cfg, "phone", _locked=True,
                    dns_pool=self._DNSPool())
            command.assert_not_called()
            journal.assert_not_called()

    def test_full_subnet_keeps_inventory_visible_and_disables_add(self):
        self.cfg["subnet"] = "10.77.0.0/30"
        with open(self.wg_conf, "w", encoding="utf-8") as handle:
            handle.write("[Interface]\nAddress = 10.77.0.1/30\nPrivateKey = server-private\n\n"
                         "[Peer]\n# phone\nPublicKey = pub\nAllowedIPs = 10.77.0.2/32\n")
        with mock.patch.object(clients, "_wg_dump", return_value={}), \
             mock.patch.object(clients, "_server_pubkey", return_value="server-public"):
            result = clients.client_inventory(self.cfg)
        self.assertEqual([row["name"] for row in result["clients"]], ["phone"])
        self.assertFalse(result["can_add"])
        self.assertIsNone(result["next_ip"])
        self.assertIn("свободных адресов", result["add_error"])

    def test_legacy_peer_keeps_all_inventory_visible_but_allocation_fail_closed(self):
        with open(self.wg_conf, "w", encoding="utf-8") as handle:
            handle.write("[Interface]\nAddress = 10.77.0.1/24\nPrivateKey = server-private\n\n"
                         "[Peer]\n# legacy\nPublicKey = old\n"
                         "AllowedIPs = 10.77.0.2/32, fd00::2/128\n\n"
                         "[Peer]\n# phone\nPublicKey = new\nAllowedIPs = 10.77.0.3/32\n")
        with mock.patch.object(clients, "_wg_dump", return_value={}), \
             mock.patch.object(clients, "_server_pubkey", return_value="server-public"):
            result = clients.client_inventory(self.cfg)
        self.assertEqual([row["name"] for row in result["clients"]], ["legacy", "phone"])
        self.assertTrue(result["clients"][0]["unsupported"])
        self.assertFalse(result["clients"][1]["unsupported"])
        self.assertFalse(result["can_add"])
        self.assertIsNone(result["next_ip"])


if __name__ == "__main__":
    unittest.main()
