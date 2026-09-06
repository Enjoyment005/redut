# -*- coding: utf-8 -*-
import json
import os
import struct
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import config_schema
import dns_probe
import dns_rescue
import dns_runtime
import pool as pool_mod


def normalized(mode="disabled", owner=False, automatic=False):
    root = tempfile.gettempdir()
    raw = {
        "config_schema_version": 2,
        "db": os.path.join(root, "dns-rescue-test.db"),
        "ring": os.path.join(root, "ring"),
        "singbox_config": os.path.join(root, "main.json"),
        "boot_script": os.path.join(root, "boot.sh"),
        "lock": os.path.join(root, "agent.lock"),
        "subnet": "10.77.0.0/24", "server_ip": "192.0.2.10", "wan": "eth0",
        "dns_rescue": {"mode": mode, "owner_approved": owner,
                       "automatic_ready": automatic, "active_probes": owner},
    }
    return config_schema.normalize(raw)


class TestDNSConfig(unittest.TestCase):
    def test_default_is_inert(self):
        cfg = normalized()
        self.assertEqual(cfg["dns_rescue"]["mode"], "disabled")
        self.assertFalse(cfg["dns_rescue"]["automatic_ready"])
        self.assertEqual(len(cfg["dns_rescue"]["candidates"]), 4)

    def test_manual_requires_owner(self):
        self.assertEqual(normalized("manual_canary", False)["dns_rescue"]["mode"], "disabled")
        self.assertEqual(normalized("manual_canary", True)["dns_rescue"]["mode"], "manual_canary")

    def test_automatic_two_operator_gate(self):
        raw = normalized("automatic_last_resort", True, True)
        self.assertEqual(raw["dns_rescue"]["mode"], "automatic_last_resort")
        self.assertTrue(raw["dns_rescue"]["automatic_ready"])
        bad = dict(raw)
        bad.pop("_config_meta", None)
        bad["dns_rescue"] = dict(raw["dns_rescue"], candidates=[raw["dns_rescue"]["candidates"][0]])
        out = config_schema.normalize(bad)
        self.assertEqual(out["dns_rescue"]["mode"], "disabled")
        self.assertFalse(out["dns_rescue"]["automatic_ready"])

    def test_hostname_or_credentials_are_rejected(self):
        cfg = normalized("manual_canary", True)
        cfg.pop("_config_meta", None)
        cfg["dns_rescue"]["candidates"] = [{
            "id": "bad", "operator": "bad", "transport": "direct",
            "endpoint": "https://user:pass@resolver.example/dns-query"}]
        out = config_schema.normalize(cfg)
        self.assertEqual(out["dns_rescue"]["mode"], "disabled")
        self.assertEqual(out["dns_rescue"]["candidates"], [])


class TestDNSWire(unittest.TestCase):
    def test_query_and_response(self):
        txid, query = dns_probe.build_query(txid=0x4242)
        self.assertEqual(txid, 0x4242)
        self.assertNotIn(b"https", query)
        response = struct.pack("!HHHHHH", txid, 0x8180, 1, 2, 0, 0) + query[12:]
        parsed = dns_probe.parse_response(response, txid)
        self.assertTrue(parsed["ok"])
        self.assertEqual(parsed["answers"], 2)

    def test_arbitrary_question_is_forbidden(self):
        with self.assertRaises(dns_probe.DNSProbeError):
            dns_probe.build_query(name="private.example")


class TestDNSPool(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.pool = pool_mod.Pool(os.path.join(self.tmp.name, "state.db"), server="test")

    def tearDown(self):
        self.pool.close()
        self.tmp.cleanup()

    def test_separate_schema_and_state(self):
        tables = {row[0] for row in self.pool.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertTrue({"dns_rescue_state", "dns_rescue_operation", "dns_probe_log"} <= tables)
        self.assertEqual(self.pool.dns_state()["phase"], "idle")
        state = self.pool.set_dns_state(phase="probing", configured_mode="manual_canary",
                                        incident_id="i1", attempt_used=True)
        self.assertEqual(state["incident_id"], "i1")

    def test_typed_idempotent_saga(self):
        op = self.pool.begin_dns_operation("i1", "activate", "slot", "all", "user", "key")
        again = self.pool.begin_dns_operation("i1", "activate", "slot", "all", "user", "key")
        self.assertEqual(op["id"], again["id"])
        for phase in ("staging", "started", "redirected", "verifying", "committed"):
            op = self.pool.transition_dns_operation(op["id"], phase)
        self.assertEqual(op["phase"], "committed")
        with self.assertRaises(ValueError):
            self.pool.transition_dns_operation(op["id"], "failed")

    def test_probe_journal_has_no_free_text_or_qname(self):
        self.pool.record_dns_probe({"ok": False, "transport": "udp", "latency_ms": 9,
                                    "error_kind": "TimeoutError", "qname": "secret.example",
                                    "error": "credential=secret"}, "i1", "slot")
        columns = {row[1] for row in self.pool.conn.execute("PRAGMA table_info(dns_probe_log)")}
        self.assertFalse({"qname", "error", "endpoint", "payload"} & columns)
        raw = json.dumps(dict(self.pool.conn.execute("SELECT * FROM dns_probe_log").fetchone()))
        self.assertNotIn("secret", raw)


class TestDNSRuntime(unittest.TestCase):
    def setUp(self):
        self.cfg = normalized("manual_canary", True)

    def test_isolated_config_direct_and_proxy(self):
        direct = next(s for s in self.cfg["dns_rescue"]["candidates"] if s["transport"] == "direct")
        built = dns_runtime.build_gateway_config(self.cfg, direct, {})
        self.assertEqual(built["inbounds"][0]["listen"], "10.77.0.1")
        self.assertNotIn("tun", json.dumps(built))
        proxy = next(s for s in self.cfg["dns_rescue"]["candidates"] if s["transport"] == "proxy")
        main = {"outbounds": [{"tag": "socks-out", "type": "socks", "server": "192.0.2.50",
                               "server_port": 1080, "username": "u", "password": "p"}]}
        via_proxy = dns_runtime.build_gateway_config(self.cfg, proxy, main)
        self.assertEqual(via_proxy["dns"]["servers"][0]["detour"], "rescue-proxy")
        self.assertEqual(via_proxy["route"]["final"], "rescue-proxy")

    def test_peer_scope_must_be_inside_wg(self):
        self.assertEqual(dns_runtime._scope_source(self.cfg, "peer:10.77.0.9"), "10.77.0.9/32")
        with self.assertRaises(dns_runtime.DNSRuntimeError):
            dns_runtime._scope_source(self.cfg, "peer:192.0.2.9")

    def test_owned_chain_never_flushes_builtin(self):
        commands = []
        def fake(command):
            commands.append(command)
            return (0, "")
        with mock.patch.object(dns_runtime.apply_mod, "run_cmd", side_effect=fake):
            dns_runtime.activate_firewall(self.cfg, scope="peer:10.77.0.9")
        self.assertIn([dns_runtime.IPTABLES, "-t", "nat", "-F", dns_runtime.CHAIN], commands)
        self.assertFalse(any(cmd[:5] == [dns_runtime.IPTABLES, "-t", "nat", "-F", "PREROUTING"]
                             for cmd in commands))


class TestCoordinator(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = normalized("manual_canary", True)
        self.cfg["db"] = os.path.join(self.tmp.name, "state.db")
        self.cfg["singbox_config"] = os.path.join(self.tmp.name, "main.json")
        with open(self.cfg["singbox_config"], "w", encoding="utf-8") as handle:
            json.dump({"outbounds": [{"tag": "socks-out", "type": "socks",
                                      "server": "192.0.2.50", "server_port": 1080}]}, handle)
        self.pool = pool_mod.Pool(self.cfg["db"], server="test")

    def tearDown(self):
        self.pool.close()
        self.tmp.cleanup()

    def test_disabled_is_fail_closed(self):
        self.cfg["dns_rescue"]["mode"] = "disabled"
        with self.assertRaises(dns_rescue.DNSRescueError):
            dns_rescue.activate(self.cfg, self.pool)

    def test_successful_activation_and_deactivation(self):
        good = {"ok": True, "results": [{"ok": True}, {"ok": True}]}
        with mock.patch.object(dns_rescue.os, "name", "posix"), \
             mock.patch.object(dns_rescue.dns_runtime, "stage_config"), \
             mock.patch.object(dns_rescue.dns_runtime, "service_start"), \
             mock.patch.object(dns_rescue.dns_runtime, "service_stop"), \
             mock.patch.object(dns_rescue.dns_runtime, "activate_firewall"), \
             mock.patch.object(dns_rescue.dns_runtime, "deactivate_firewall", return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "firewall_effective", side_effect=[True, False]), \
             mock.patch.object(dns_rescue, "probe_listener", return_value=good):
            active = dns_rescue.activate(self.cfg, self.pool, _locked=True)
            self.assertTrue(active["ok"])
            self.assertEqual(active["state"]["phase"], "active_proxy")
            idle = dns_rescue.deactivate(self.cfg, self.pool, _locked=True)
            self.assertTrue(idle["ok"])
            self.assertEqual(idle["state"]["phase"], "idle")

    def test_activation_failure_rolls_back(self):
        with mock.patch.object(dns_rescue.os, "name", "posix"), \
             mock.patch.object(dns_rescue.dns_runtime, "stage_config"), \
             mock.patch.object(dns_rescue.dns_runtime, "service_start"), \
             mock.patch.object(dns_rescue.dns_runtime, "service_stop"), \
             mock.patch.object(dns_rescue.dns_runtime, "deactivate_firewall", return_value=True), \
             mock.patch.object(dns_rescue, "probe_listener", return_value={"ok": False}):
            result = dns_rescue.activate(self.cfg, self.pool, _locked=True)
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"]["phase"], "failed")
        self.assertEqual(self.pool.dns_operations()[0]["phase"], "rolled_back")

    def test_auto_is_one_shot_and_needs_exhaustion(self):
        self.cfg = normalized("automatic_last_resort", True, True)
        self.pool.set_setting("dns_recovery_exhausted", "1")
        self.pool.set_dns_state(phase="idle", configured_mode="automatic_last_resort",
                                attempt_used=True)
        result = dns_rescue.automatic_tick(self.cfg, self.pool, "EMERGENCY")
        self.assertEqual(result["action"], "ineligible")


if __name__ == "__main__":
    unittest.main()
