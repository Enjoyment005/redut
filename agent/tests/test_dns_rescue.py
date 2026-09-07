# -*- coding: utf-8 -*-
import datetime
import json
import os
import struct
import sys
import tempfile
import time
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
    rescue = {"mode": mode, "owner_approved": owner,
              "automatic_ready": automatic, "active_probes": owner}
    if owner:
        rescue.update({
            "canary_runner_sha256": "a" * 64,
            "canary_peer_ipv4": "10.77.0.9",
            "canary_qname_suffix": "canary.redut.example",
            "canary_expected_ipv4": "192.0.2.53",
            "candidates": [
                {"id": "cloudflare-proxy", "operator": "cloudflare",
                 "endpoint": "https://1.1.1.1/dns-query", "transport": "proxy",
                 "sni": "1.1.1.1", "address_generation": "test-v1",
                 "not_after": "2999-01-01T00:00:00Z"},
                {"id": "google-proxy", "operator": "google",
                 "endpoint": "https://8.8.8.8/dns-query", "transport": "proxy",
                 "sni": "8.8.8.8", "address_generation": "test-v1",
                 "not_after": "2999-01-01T00:00:00Z"},
                {"id": "cloudflare-direct", "operator": "cloudflare",
                 "endpoint": "https://1.1.1.1/dns-query", "transport": "direct",
                 "sni": "1.1.1.1", "address_generation": "test-v1",
                 "not_after": "2999-01-01T00:00:00Z"},
                {"id": "google-direct", "operator": "google",
                 "endpoint": "https://8.8.8.8/dns-query", "transport": "direct",
                 "sni": "8.8.8.8", "address_generation": "test-v1",
                 "not_after": "2999-01-01T00:00:00Z"},
            ],
        })
    if automatic:
        rescue.update({
            "canary_evidence_id": "test-canary-2026-09",
            "rollback_drill_passed": True,
            "firewall_drill_evidence_id": "test-firewall-2026-09",
            "clock_evidence_id": "test-clock-2026-09",
            "resource_slo_evidence_id": "test-resource-2026-09",
            "leak_policy_evidence_id": "test-leak-2026-09",
            "readiness_not_after": "2999-01-01T00:00:00Z",
            "profile_classes_ready": ["wg-ip", "external-ip"],
        })
    raw = {
        "config_schema_version": 2,
        "db": os.path.join(root, "dns-rescue-test.db"),
        "ring": os.path.join(root, "ring"),
        "singbox_config": os.path.join(root, "main.json"),
        "boot_script": os.path.join(root, "boot.sh"),
        "lock": os.path.join(root, "agent.lock"),
        "subnet": "10.77.0.0/24", "server_ip": "192.0.2.10", "wan": "eth0",
        "dns_rescue": rescue,
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
        self.assertEqual(out["dns_rescue"]["mode"], "automatic_last_resort")
        self.assertFalse(out["dns_rescue"]["automatic_ready"])

    def test_automatic_gate_requires_exact_canary_peer(self):
        raw = normalized("automatic_last_resort", True, True)
        raw.pop("_config_meta", None)
        raw["dns_rescue"]["canary_peer_ipv4"] = ""
        out = config_schema.normalize(raw)
        self.assertEqual(out["dns_rescue"]["mode"], "automatic_last_resort")
        self.assertFalse(out["dns_rescue"]["automatic_ready"])

    def test_automatic_gate_requires_complete_live_evidence_pack(self):
        raw = normalized("automatic_last_resort", True, True)
        raw.pop("_config_meta", None)
        raw["dns_rescue"]["clock_evidence_id"] = ""
        out = config_schema.normalize(raw)
        self.assertEqual(out["dns_rescue"]["mode"], "automatic_last_resort")
        self.assertFalse(out["dns_rescue"]["automatic_ready"])

    def test_active_probes_false_closes_automatic_readiness(self):
        raw = normalized("automatic_last_resort", True, True)
        raw.pop("_config_meta", None)
        raw["dns_rescue"]["active_probes"] = False
        out = config_schema.normalize(raw)
        self.assertEqual(out["dns_rescue"]["mode"], "automatic_last_resort")
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

    def test_fake_operator_or_same_endpoint_ip_cannot_satisfy_diversity(self):
        cfg = normalized("automatic_last_resort", True, True)
        cfg.pop("_config_meta", None)
        cfg["dns_rescue"]["candidates"][1].update({
            "operator": "fake-google", "endpoint": "https://1.1.1.1/resolve",
            "sni": "1.1.1.1"})
        out = config_schema.normalize(cfg)
        self.assertEqual(out["dns_rescue"]["mode"], "disabled")
        self.assertFalse(out["dns_rescue"]["automatic_ready"])

    def test_time_helpers_preserve_ttl_and_intervals(self):
        self.assertGreater(dns_rescue._age("2000-01-01T00:00:00Z"), 0)
        self.assertLess(dns_rescue._age("2999-01-01T00:00:00Z"), 0)
        self.assertTrue(dns_rescue._is_future("2999-01-01T00:00:00Z"))
        self.assertFalse(dns_rescue._is_future("2000-01-01T00:00:00Z"))


class TestDNSWire(unittest.TestCase):
    def test_query_and_response(self):
        txid, query = dns_probe.build_query(txid=0x4242)
        self.assertEqual(txid, 0x4242)
        self.assertNotIn(b"https", query)
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\xc0\x00\x02\x01"
        response = struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0) + query[12:] + answer
        parsed = dns_probe.parse_response(response, txid)
        self.assertTrue(parsed["ok"])
        self.assertEqual(parsed["answers"], 1)

    def test_arbitrary_question_is_forbidden(self):
        with self.assertRaises(dns_probe.DNSProbeError):
            dns_probe.build_query(name="private.example")

    def test_response_question_must_match_fixed_probe(self):
        txid, _query = dns_probe.build_query(txid=0x4242)
        other = b"\x07private\x07example\x00" + struct.pack("!HH", 1, 1)
        response = struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0) + other
        with self.assertRaises(dns_probe.DNSProbeError):
            dns_probe.parse_response(response, txid)

    def test_response_claiming_missing_answer_is_rejected(self):
        txid, query = dns_probe.build_query(txid=0x4242)
        response = struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0) + query[12:]
        with self.assertRaises(dns_probe.DNSProbeError):
            dns_probe.parse_response(response, txid)

    def test_owned_canary_requires_exact_owner_and_expected_ipv4(self):
        name = "0123456789abcdef0123456789abcdef.canary.redut.example"
        txid, query = dns_probe._build_query(0x4242, name)
        other_owner = dns_probe._question_wire("other.canary.redut.example")[:-4]
        answer = (other_owner + struct.pack("!HHIH", 1, 1, 30, 4)
                  + b"\xc0\x00\x02\x35")
        response = (struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0)
                    + query[12:] + answer)
        self.assertFalse(dns_probe.parse_response(
            response, txid, name=name, expected_ipv4="192.0.2.53")["ok"])

    def test_owned_canary_rejects_cache_ttl_above_contract(self):
        name = "0123456789abcdef0123456789abcdef.canary.redut.example"
        txid, query = dns_probe._build_query(0x4242, name)
        answer = (b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 301, 4)
                  + b"\xc0\x00\x02\x35")
        response = (struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0)
                    + query[12:] + answer)
        self.assertFalse(dns_probe.parse_response(
            response, txid, name=name, expected_ipv4="192.0.2.53")["ok"])

        exact_answer = (b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4)
                        + b"\xc0\x00\x02\x36")
        response = (struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0)
                    + query[12:] + exact_answer)
        self.assertFalse(dns_probe.parse_response(
            response, txid, name=name, expected_ipv4="192.0.2.53")["ok"])


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

    def test_activation_state_and_saga_commit_are_one_sql_transaction(self):
        operation = self.pool.begin_dns_operation(
            "i-atomic", "activate-node_wide_automatic", "slot-a", "all",
            "auto", "atomic-key", generation="generation-a",
            profile_class="all-present")
        for phase in ("staging", "started", "redirected", "verifying"):
            operation = self.pool.transition_dns_operation(operation["id"], phase)
        state = self.pool.commit_dns_activation(
            operation["id"], phase="active_proxy", configured_mode="automatic_last_resort",
            incident_id="i-atomic", active_scope="all", active_slot="slot-a",
            generation="generation-a", active_kind="node_wide_automatic")
        self.assertEqual(state["phase"], "active_proxy")
        committed = next(row for row in self.pool.dns_operations()
                         if row["id"] == operation["id"])
        self.assertEqual(committed["phase"], "committed")

        mismatch = self.pool.begin_dns_operation(
            "i-bad", "activate-node_wide_automatic", "slot-b", "all",
            "auto", "atomic-bad", generation="generation-b",
            profile_class="all-present")
        for phase in ("staging", "started", "redirected", "verifying"):
            mismatch = self.pool.transition_dns_operation(mismatch["id"], phase)
        with self.assertRaises(ValueError):
            self.pool.commit_dns_activation(
                mismatch["id"], phase="active_proxy",
                configured_mode="automatic_last_resort", incident_id="i-bad",
                active_scope="all", active_slot="slot-b",
                generation="different", active_kind="node_wide_automatic")
        still_verifying = next(row for row in self.pool.dns_operations()
                               if row["id"] == mismatch["id"])
        self.assertEqual(still_verifying["phase"], "verifying")
        self.assertEqual(self.pool.dns_state()["incident_id"], "i-atomic")

    def test_probe_journal_has_no_free_text_or_qname(self):
        self.pool.record_dns_probe({"ok": False, "transport": "udp", "latency_ms": 9,
                                    "error_kind": "TimeoutError", "qname": "secret.example",
                                    "error": "credential=secret"}, "i1", "slot")
        columns = {row[1] for row in self.pool.conn.execute("PRAGMA table_info(dns_probe_log)")}
        self.assertFalse({"qname", "error", "endpoint", "payload"} & columns)
        raw = json.dumps(dict(self.pool.conn.execute("SELECT * FROM dns_probe_log").fetchone()))
        self.assertNotIn("secret", raw)

    def test_prune_preserves_all_operations_for_current_incident(self):
        current = self.pool.begin_dns_operation(
            "incident-current", "activate-isolated_manual", "slot-current",
            "peer:10.77.0.9", "user", "key-current",
            profile_class="wg-ip", generation="generation-current",
            expires_at="2999-01-01 00:15:00")
        for phase in ("staging", "started", "redirected", "verifying"):
            current = self.pool.transition_dns_operation(current["id"], phase)
        self.pool.commit_dns_activation(
            current["id"], phase="active_isolated",
            configured_mode="manual_canary", incident_id="incident-current",
            active_scope="peer:10.77.0.9", active_slot="slot-current",
            active_kind="isolated_manual", generation="generation-current",
            expires_at="2999-01-01 00:15:00", expires_monotonic=999999999.0,
            scope_identity="scope-test", boot_id="boot-test")
        old = self.pool.begin_dns_operation(
            "incident-old", "activate-isolated_manual", "slot-old",
            "peer:10.77.0.8", "user", "key-old",
            profile_class="wg-ip", generation="generation-old")
        self.pool.transition_dns_operation(old["id"], "failed")
        ancient = "2000-01-01 00:00:00"
        self.pool.conn.execute(
            "UPDATE dns_rescue_operation SET finished_at=?", (ancient,))
        self.pool.conn.commit()
        result = self.pool.prune(
            now=datetime.datetime(2026, 9, 6, 12, 0, 0))
        self.assertEqual(result["dns_operations"], 1)
        self.assertEqual(self.pool.tried_dns_activation_slots(
            "incident-current"), {"slot-current"})
        profile = self.pool.committed_dns_activation_profile(
            "incident-current", "slot-current", "peer:10.77.0.9",
            "generation-current")
        self.assertEqual(profile, "wg-ip")


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
        def fake(command, **_kwargs):
            commands.append(command)
            if (command[:4] == [dns_runtime.IPTABLES, "-t", "nat", "-S"]
                    and command[4] == dns_runtime.PRIMARY_TEST_CHAIN):
                return (1, "missing")
            return (0, "")
        with mock.patch.object(dns_runtime.apply_mod, "run_cmd", side_effect=fake), \
             mock.patch.object(dns_runtime, "_firewall_attached_strict",
                               return_value=True), \
             mock.patch.object(dns_runtime, "_listener_acl_effective",
                               return_value=True), \
             mock.patch.object(
                 dns_runtime, "_conntrack_cmd",
                 side_effect=lambda command, *_args, **_kwargs:
                 ((1, "0 flow entries have been deleted", "")
                  if "-D" in command else (0, "<conntrack />", ""))), \
             mock.patch.object(dns_runtime, "_delete_rule_all"):
            dns_runtime.activate_firewall(self.cfg, scope="peer:10.77.0.9")
        self.assertIn([dns_runtime.IPTABLES, "-t", "nat", "-F",
                       dns_runtime.SCOPED_CHAIN], commands)
        self.assertFalse(any(cmd[:5] == [dns_runtime.IPTABLES, "-t", "nat", "-F", "PREROUTING"]
                             for cmd in commands))

    def test_stage_config_fsyncs_parent_and_verifies_live_bytes(self):
        direct = next(s for s in self.cfg["dns_rescue"]["candidates"]
                      if s["transport"] == "direct")
        with tempfile.TemporaryDirectory() as root:
            target = os.path.join(root, "config.json")
            with mock.patch.object(dns_runtime, "_cmd", return_value=(0, "")), \
                 mock.patch.object(dns_runtime.os, "name", "nt"), \
                 mock.patch.object(dns_runtime, "_fsync_directory") as fsync_dir:
                built = dns_runtime.stage_config(self.cfg, direct, {}, path=target)
            fsync_dir.assert_called_once_with(root)
            with open(target, encoding="utf-8") as handle:
                self.assertEqual(json.load(handle), built)

    def test_command_timeout_is_capped_by_shared_deadline(self):
        with mock.patch.object(dns_runtime.time, "monotonic", return_value=100.25), \
             mock.patch.object(dns_runtime.apply_mod, "run_cmd",
                               return_value=(0, "ok")) as run:
            self.assertEqual(dns_runtime._cmd(["probe"], 101.0, cap=5.0), (0, "ok"))
        self.assertAlmostEqual(run.call_args.kwargs["timeout"], 0.75)

    def test_sidecar_cleanup_proves_process_dead_before_removing_acl(self):
        order = []
        with mock.patch.object(dns_runtime, "_preflight_service_stop",
                               side_effect=lambda *_a: order.append("stop")), \
             mock.patch.object(dns_runtime, "_scrub_preflight_acl",
                               side_effect=lambda *_a: order.append("acl")), \
             mock.patch.object(dns_runtime.os.path, "exists", return_value=False):
            dns_runtime.scrub_candidate_sidecar(self.cfg)
        self.assertEqual(order, ["stop", "acl"])

    def test_sidecar_uses_fixed_transient_systemd_unit(self):
        commands = []

        def fake_cmd(command, *_args, **_kwargs):
            commands.append(command)
            if command[:2] == ["systemctl", "is-active"]:
                return (4, "unknown") if len(commands) == 1 else (0, "active")
            return (0, "")

        with mock.patch.object(dns_runtime, "_cmd", side_effect=fake_cmd):
            dns_runtime._preflight_service_start(self.cfg)
        launch = next(command for command in commands if command[0] == "systemd-run")
        self.assertIn("--unit=" + dns_runtime.PREFLIGHT_UNIT, launch)
        self.assertIn("--uid=redut-dns", launch)
        self.assertIn("--property=RuntimeMaxSec=45s", launch)
        self.assertNotIn("Popen", dns_runtime.candidate_sidecar_preflight_proven.__code__.co_names)


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

    def _seed_nodewide_committed(self, kind="node_wide_automatic",
                                 manual_ref=None, boot_id="boot-old"):
        operation = self.pool.begin_dns_operation(
            "dns-boot", "activate-" + kind, "cloudflare-proxy", "all",
            "auto", "seed-" + kind, profile_class="all-present",
            generation="generation-old",
            snapshot={"manual_emergency_ref": manual_ref})
        for phase in ("staging", "started", "redirected", "verifying"):
            operation = self.pool.transition_dns_operation(operation["id"], phase)
        return self.pool.commit_dns_activation(
            operation["id"], phase="active_proxy", configured_mode="manual_canary",
            incident_id="dns-boot", active_scope="all",
            active_slot="cloudflare-proxy", active_kind=kind,
            generation="generation-old", scope_identity="scope-test",
            boot_id=boot_id, backend_last_ok=dns_rescue._now(),
            client_path_last_ok=dns_rescue._now(),
            manual_emergency_ref=manual_ref)

    def _resume_success(self, setting_key, state):
        """Model the atomic descriptor CAS performed by real activation."""
        def complete(*_args, **kwargs):
            self.assertEqual(kwargs.get("clear_resume_setting"), setting_key)
            descriptor = json.loads(self.pool.get_setting(setting_key))
            self.assertEqual(kwargs.get("clear_resume_id"), descriptor["resume_id"])
            self.pool.set_setting(setting_key, None)
            self.pool.set_dns_state(**{
                key: value for key, value in state.items()
                if key in {
                    "phase", "configured_mode", "incident_id", "active_scope",
                    "active_slot", "activated_at", "attempt_used",
                    "return_successes", "last_error", "active_kind",
                    "expires_at", "active_failures", "active_last_check",
                    "return_last_check", "generation", "backend_last_ok",
                    "client_path_last_ok", "scope_identity", "boot_id",
                    "expires_monotonic", "manual_emergency_ref",
                }
            })
            return {"ok": True, "action": "activated", "state": self.pool.dns_state()}
        return complete

    def test_disabled_is_fail_closed(self):
        self.cfg["dns_rescue"]["mode"] = "disabled"
        with self.assertRaises(dns_rescue.DNSRescueError):
            dns_rescue.activate(self.cfg, self.pool)

    def test_active_probes_false_blocks_new_manual_before_operation_or_probe(self):
        self.cfg["dns_rescue"]["active_probes"] = False
        with mock.patch.object(dns_rescue, "probe_backend") as probe:
            with self.assertRaisesRegex(dns_rescue.DNSRescueError,
                                        "active DNS probes are disabled"):
                dns_rescue.activate(
                    self.cfg, self.pool, scope="peer:10.77.0.9",
                    profile_class="wg-ip", _locked=True)
        probe.assert_not_called()
        self.assertEqual(self.pool.dns_operations(), [])

    def test_active_probes_false_blocks_new_automatic_before_causal_probe(self):
        self.cfg = normalized("automatic_last_resort", True, True)
        self.cfg["dns_rescue"]["active_probes"] = False
        self.pool.set_settings({"dns_recovery_exhausted": "1",
                                "dns_incident_id": "dns-no-probes",
                                "automat_state": "EMERGENCY"})
        with mock.patch.object(dns_rescue.dns_runtime,
                               "client_primary_failure_proven") as causal, \
             mock.patch.object(dns_rescue, "_primary_dns_failure") as primary, \
             mock.patch.object(dns_rescue, "probe_backend") as backend:
            result = dns_rescue.automatic_tick(
                self.cfg, self.pool, "EMERGENCY", _locked=True)
        self.assertEqual(result["action"], "ineligible")
        self.assertFalse(result["state"].get("attempt_used"))
        causal.assert_not_called()
        primary.assert_not_called()
        backend.assert_not_called()
        self.assertEqual(self.pool.dns_operations(), [])

    def test_observe_uses_isolated_candidate_sidecar_not_live_listener(self):
        self.cfg["dns_rescue"].update(
            mode="observe_only", profile_classes_ready=["wg-ip", "external-ip"])
        lock = mock.MagicMock()
        lock.__enter__.return_value = lock
        with mock.patch.object(dns_rescue.os, "name", "posix"), \
             mock.patch.object(dns_rescue.apply_mod, "Flock", return_value=lock), \
             mock.patch.object(dns_rescue.dns_runtime, "peer_canary_runner_ready",
                               return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "wireguard_scope_ready",
                               return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "candidate_sidecar_preflight_proven",
                               return_value=True) as sidecar, \
             mock.patch.object(dns_rescue, "probe_backend") as live_probe:
            result = dns_rescue.observe(self.cfg, self.pool)
        self.assertTrue(result["ok"])
        self.assertEqual(sidecar.call_count, 4)
        live_probe.assert_not_called()

    def test_observe_never_starts_sidecar_after_candidate_expiry_boundary(self):
        self.cfg["dns_rescue"].update(
            mode="observe_only", profile_classes_ready=["wg-ip", "external-ip"])
        lock = mock.MagicMock()
        lock.__enter__.return_value = lock
        with mock.patch.object(dns_rescue.os, "name", "posix"), \
             mock.patch.object(dns_rescue.apply_mod, "Flock", return_value=lock), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "peer_canary_runner_ready", return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "wireguard_scope_ready", return_value=True), \
             mock.patch.object(dns_rescue, "_slots", return_value=[
                 self.cfg["dns_rescue"]["candidates"][0]]), \
             mock.patch.object(dns_rescue, "_is_future",
                               side_effect=[True, False]), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "candidate_sidecar_preflight_proven") as sidecar:
            result = dns_rescue.observe(self.cfg, self.pool)
        self.assertFalse(result["ok"])
        self.assertEqual(result["results"][0]["error_kind"], "DNSRescueError")
        sidecar.assert_not_called()

    def test_durable_continuation_survives_closed_new_activation_gate(self):
        self.cfg["dns_rescue"].update(
            mode="disabled", owner_approved=False, automatic_ready=False)
        with self.assertRaises(dns_rescue.DNSRescueError):
            dns_rescue._allowed(self.cfg, automatic=True, continuation=False)
        dns_rescue._allowed(self.cfg, automatic=True, continuation=True)

    def test_frozen_automatic_allows_only_exact_active_continuation(self):
        self.cfg = normalized("automatic_last_resort", True, True)
        self.pool.set_settings({"automat_state": "EMERGENCY",
                                "automat_frozen": "1",
                                "dns_recovery_exhausted": "1"})
        with mock.patch.object(dns_rescue.os, "name", "posix"), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "peer_canary_runner_ready", return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "emergency_route_ready", return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "wireguard_scope_ready", return_value=True):
            with self.assertRaisesRegex(dns_rescue.DNSRescueError, "paused"):
                dns_rescue._validate_scope_locked(
                    self.cfg, self.pool, "all", automatic=True,
                    continuation=False, profile_class="all-present")
            dns_rescue._validate_scope_locked(
                self.cfg, self.pool, "all", automatic=True,
                continuation=True, profile_class="all-present")

    def test_node_wide_manual_requires_configured_live_canary_peer(self):
        self.cfg["dns_rescue"]["canary_peer_ipv4"] = ""
        self.pool.set_settings({"automat_state": "EMERGENCY",
                                "emergency_manual": "1",
                                "manual_emergency_ref": "manual-ref"})
        with mock.patch.object(dns_rescue.os, "name", "posix"), \
             mock.patch.object(dns_rescue.dns_runtime, "peer_canary_runner_ready",
                               return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "emergency_route_ready",
                               return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "wireguard_scope_ready",
                               return_value=True):
            with self.assertRaisesRegex(dns_rescue.DNSRescueError,
                                        "synthetic WG canary peer"):
                dns_rescue._validate_scope_locked(
                    self.cfg, self.pool, "all", automatic=False)

    def test_node_wide_manual_requires_effective_emergency_route(self):
        self.pool.set_settings({"automat_state": "EMERGENCY",
                                "emergency_manual": "1",
                                "manual_emergency_ref": "manual-ref"})
        with mock.patch.object(dns_rescue.os, "name", "posix"), \
             mock.patch.object(dns_rescue.dns_runtime, "peer_canary_runner_ready",
                               return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "emergency_route_ready",
                               return_value=False):
            with self.assertRaisesRegex(dns_rescue.DNSRescueError,
                                        "direct EMERGENCY route"):
                dns_rescue._validate_scope_locked(
                    self.cfg, self.pool, "all", automatic=False)

    def test_successful_activation_and_deactivation(self):
        good = {"ok": True, "results": [{"ok": True}, {"ok": True}]}
        with mock.patch.object(dns_rescue.os, "name", "posix"), \
             mock.patch.object(dns_rescue, "_boot_id", return_value="boot-test"), \
             mock.patch.object(dns_rescue.dns_runtime, "wireguard_scope_ready", return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "wireguard_scope_identity", return_value="scope-test"), \
             mock.patch.object(dns_rescue.dns_runtime, "peer_canary_runner_ready", return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "stage_config"), \
             mock.patch.object(dns_rescue.dns_runtime, "stage_listener_acl"), \
             mock.patch.object(dns_rescue.dns_runtime, "service_start"), \
             mock.patch.object(dns_rescue.dns_runtime, "service_stop"), \
             mock.patch.object(dns_rescue.dns_runtime, "service_inactive", return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "service_active", return_value=False), \
             mock.patch.object(dns_rescue.dns_runtime, "activate_firewall"), \
             mock.patch.object(dns_rescue.dns_runtime, "deactivate_redirect", return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "redirect_detached", return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "remove_listener_acl", return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "firewall_attached", return_value=False), \
             mock.patch.object(dns_rescue.dns_runtime, "firewall_detached", return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "firewall_effective", return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "client_roundtrip_proven", return_value=True), \
             mock.patch.object(dns_rescue, "probe_backend", return_value=good):
            active = dns_rescue.activate(self.cfg, self.pool, scope="peer:10.77.0.9",
                                         profile_class="wg-ip", _locked=True)
            self.assertTrue(active["ok"])
            self.assertEqual(active["state"]["phase"], "active_isolated")
            self.assertEqual(active["state"]["active_kind"], "isolated_manual")
            idle = dns_rescue.deactivate(self.cfg, self.pool, _locked=True)
            self.assertTrue(idle["ok"])
            self.assertEqual(idle["state"]["phase"], "idle")

    def test_activation_failure_rolls_back(self):
        with mock.patch.object(dns_rescue.os, "name", "posix"), \
             mock.patch.object(dns_rescue, "_boot_id", return_value="boot-test"), \
             mock.patch.object(dns_rescue.dns_runtime, "wireguard_scope_ready", return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "wireguard_scope_identity", return_value="scope-test"), \
             mock.patch.object(dns_rescue.dns_runtime, "peer_canary_runner_ready", return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "stage_config"), \
             mock.patch.object(dns_rescue.dns_runtime, "stage_listener_acl"), \
             mock.patch.object(dns_rescue.dns_runtime, "service_start"), \
             mock.patch.object(dns_rescue.dns_runtime, "service_stop"), \
             mock.patch.object(dns_rescue.dns_runtime, "service_inactive", return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "service_active", return_value=False), \
             mock.patch.object(dns_rescue.dns_runtime, "deactivate_redirect", return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "redirect_detached", return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "remove_listener_acl", return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "firewall_attached", return_value=False), \
             mock.patch.object(dns_rescue, "probe_backend", return_value={"ok": False}):
            result = dns_rescue.activate(self.cfg, self.pool, scope="peer:10.77.0.9",
                                         profile_class="wg-ip", _locked=True)
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"]["phase"], "idle")
        self.assertEqual(self.pool.dns_operations()[0]["phase"], "rolled_back")

    def test_automatic_gate_requires_real_external_canary_runner(self):
        self.cfg = normalized("automatic_last_resort", True, True)
        self.pool.set_settings({"dns_recovery_exhausted": "1",
                                "dns_incident_id": "dns-1",
                                "automat_state": "EMERGENCY"})
        with mock.patch.object(dns_rescue.dns_runtime, "emergency_route_ready",
                               return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "wireguard_scope_ready",
                               return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "peer_canary_runner_ready",
                               return_value=False), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "client_primary_failure_proven") as client, \
             mock.patch.object(dns_rescue, "_primary_dns_failure") as primary:
            result = dns_rescue.automatic_tick(
                self.cfg, self.pool, "EMERGENCY", _locked=True)
        self.assertEqual(result["action"], "canary-runner-unavailable")
        client.assert_not_called()
        primary.assert_not_called()

    def test_node_wide_candidate_is_preflighted_before_global_redirect(self):
        main_config = self.cfg["singbox_config"]
        self.cfg = normalized("automatic_last_resort", True, True)
        self.cfg["db"] = os.path.join(self.tmp.name, "state-auto.db")
        self.cfg["singbox_config"] = main_config
        self.pool.set_settings({"dns_recovery_exhausted": "1",
                                "dns_incident_id": "dns-order",
                                "automat_state": "EMERGENCY"})
        order = []
        good = {"ok": True, "results": [{"ok": True}, {"ok": True}]}

        def stage_acl(_cfg, scope="all", **_kwargs):
            order.append("acl:" + scope)

        def activate_firewall(_cfg, scope="all", **_kwargs):
            order.append("redirect:" + scope)
            return True

        runtime_mocks = {
            "emergency_route_ready": mock.Mock(return_value=True),
            "wireguard_scope_ready": mock.Mock(return_value=True),
            "wireguard_scope_identity": mock.Mock(return_value="scope-test"),
            "peer_canary_runner_ready": mock.Mock(return_value=True),
            "firewall_attached": mock.Mock(return_value=False),
            "service_active": mock.Mock(return_value=False),
            "stage_config": mock.Mock(),
            "stage_listener_acl": mock.Mock(side_effect=stage_acl),
            "service_start": mock.Mock(
                side_effect=lambda *_a, **_k: order.append("start")),
            "service_stop": mock.Mock(
                side_effect=lambda *_a, **_k: order.append("stop")),
            "remove_listener_acl": mock.Mock(
                side_effect=lambda *_a, **_k: order.append("remove-acl")),
            "client_candidate_preflight_proven": mock.Mock(
                side_effect=lambda *_a, **_k: order.append("preflight") or True),
            "client_primary_failure_proven": mock.Mock(return_value=True),
            "activate_firewall": mock.Mock(side_effect=activate_firewall),
            "deactivate_redirect": mock.Mock(return_value=True),
            "redirect_detached": mock.Mock(return_value=True),
            "firewall_effective": mock.Mock(return_value=True),
            "client_roundtrip_proven": mock.Mock(return_value=True),
        }
        with mock.patch.object(dns_rescue.os, "name", "posix"), \
             mock.patch.object(dns_rescue, "_boot_id", return_value="boot-test"), \
             mock.patch.multiple(dns_rescue.dns_runtime, **runtime_mocks), \
             mock.patch.object(dns_rescue, "probe_backend", return_value=good):
            result = dns_rescue.activate(
                self.cfg, self.pool, automatic=True, incident_id="dns-order",
                _locked=True)
        self.assertTrue(result["ok"], result)
        self.assertLess(order.index("acl:peer:10.77.0.9"), order.index("preflight"))
        self.assertLess(order.index("redirect:peer:10.77.0.9"), order.index("preflight"))
        self.assertLess(order.index("preflight"), order.index("acl:all"))
        self.assertLess(order.index("acl:all"), order.index("redirect:all"))

    def test_auto_is_one_shot_and_needs_exhaustion(self):
        self.cfg = normalized("automatic_last_resort", True, True)
        self.pool.set_setting("dns_recovery_exhausted", "1")
        self.pool.set_dns_state(phase="idle", configured_mode="automatic_last_resort",
                                attempt_used=True)
        result = dns_rescue.automatic_tick(self.cfg, self.pool, "EMERGENCY")
        self.assertEqual(result["action"], "ineligible")

    def test_client_primary_unproven_is_reserved_once_per_incident(self):
        self.cfg = normalized("automatic_last_resort", True, True)
        self.pool.set_settings({"dns_recovery_exhausted": "1",
                                "dns_incident_id": "dns-client-unproven",
                                "automat_state": "EMERGENCY"})
        with mock.patch.object(dns_rescue.dns_runtime, "emergency_route_ready",
                               return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "wireguard_scope_ready",
                               return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "peer_canary_runner_ready",
                               return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "client_primary_failure_proven",
                               return_value=False) as client:
            first = dns_rescue.automatic_tick(
                self.cfg, self.pool, "EMERGENCY", _locked=True)
            second = dns_rescue.automatic_tick(
                self.cfg, self.pool, "EMERGENCY", _locked=True)
        self.assertEqual(first["action"], "client-primary-unproven")
        self.assertEqual(second["action"], "ineligible")
        self.assertEqual(client.call_count, 1)
        self.assertTrue(self.pool.dns_state()["attempt_used"])

    def test_primary_dns_working_probe_is_reserved_once_per_incident(self):
        self.cfg = normalized("automatic_last_resort", True, True)
        self.pool.set_settings({"dns_recovery_exhausted": "1",
                                "dns_incident_id": "dns-server-working",
                                "automat_state": "EMERGENCY"})
        with mock.patch.object(dns_rescue.dns_runtime, "emergency_route_ready",
                               return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "wireguard_scope_ready",
                               return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "peer_canary_runner_ready",
                               return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "client_primary_failure_proven",
                               return_value=True), \
             mock.patch.object(dns_rescue, "_primary_dns_failure",
                               return_value=(False, [])) as primary:
            first = dns_rescue.automatic_tick(
                self.cfg, self.pool, "EMERGENCY", _locked=True)
            second = dns_rescue.automatic_tick(
                self.cfg, self.pool, "EMERGENCY", _locked=True)
        self.assertEqual(first["action"], "primary-dns-working")
        self.assertEqual(second["action"], "ineligible")
        self.assertEqual(primary.call_count, 1)

    def test_recovering_state_never_starts_health_or_failover(self):
        self.pool.set_dns_state(
            phase="recovering", active_scope="all",
            active_slot="cloudflare-proxy", active_kind="node_wide_automatic")
        with mock.patch.object(dns_rescue.dns_runtime,
                               "emergency_route_ready") as route, \
             mock.patch.object(dns_rescue.dns_runtime,
                               "wireguard_scope_identity") as identity, \
             mock.patch.object(dns_rescue, "probe_backend") as probe, \
             mock.patch.object(dns_rescue, "_failover_locked") as failover:
            result = dns_rescue.automatic_tick(
                self.cfg, self.pool, "EMERGENCY", _locked=True)
        self.assertEqual(result["action"], "cleanup-pending")
        route.assert_not_called()
        identity.assert_not_called()
        probe.assert_not_called()
        failover.assert_not_called()

    def test_reconcile_detaches_dead_listener_before_any_restart(self):
        order = []
        with mock.patch.object(dns_rescue.os, "name", "posix"), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "scrub_candidate_sidecar"), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "scrub_primary_test_bypass"), \
             mock.patch.object(dns_rescue.dns_runtime, "firewall_attached",
                               return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "deactivate_redirect",
                               side_effect=lambda *_a, **_k: order.append("detach") or True), \
             mock.patch.object(dns_rescue.dns_runtime, "redirect_detached",
                               return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "service_stop",
                               side_effect=lambda *_a, **_k: order.append("stop")), \
             mock.patch.object(dns_rescue.dns_runtime, "remove_listener_acl",
                               side_effect=lambda *_a, **_k: order.append("acl")), \
             mock.patch.object(dns_rescue.dns_runtime, "service_start") as start:
            state = dns_rescue.reconcile(self.cfg, self.pool, _locked=True)
        self.assertEqual(order, ["detach", "stop", "acl"])
        start.assert_not_called()
        self.assertEqual(state["phase"], "failed")

    def test_auxiliary_cleanup_failure_cannot_block_main_nat_detach(self):
        with mock.patch.object(dns_rescue.os, "name", "posix"), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "scrub_candidate_sidecar",
                               side_effect=dns_runtime.DNSRuntimeError("busy")), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "scrub_primary_test_bypass"), \
             mock.patch.object(dns_rescue.dns_runtime, "firewall_attached",
                               return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "deactivate_redirect",
                               return_value=True) as detach, \
             mock.patch.object(dns_rescue.dns_runtime, "redirect_detached",
                               return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "service_stop"), \
             mock.patch.object(dns_rescue.dns_runtime, "remove_listener_acl"):
            dns_rescue.reconcile(self.cfg, self.pool, _locked=True)
        detach.assert_called_once()

    def test_crashed_scoped_preflight_never_recovers_with_all_scope_acl(self):
        operation = self.pool.begin_dns_operation(
            "manual-scope-crash", "activate-isolated_manual",
            "cloudflare-proxy", "peer:10.77.0.9", "user",
            "scoped-preflight-crash", profile_class="wg-ip",
            generation="generation-scope")
        for phase in ("staging", "started"):
            operation = self.pool.transition_dns_operation(operation["id"], phase)
        guards = []
        with mock.patch.object(dns_rescue.os, "name", "posix"), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "scrub_candidate_sidecar"), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "scrub_primary_test_bypass"), \
             mock.patch.object(dns_rescue.dns_runtime, "firewall_attached",
                               return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "deactivate_redirect",
                               side_effect=dns_runtime.DNSRuntimeError("unknown")), \
             mock.patch.object(dns_rescue.dns_runtime, "redirect_detached",
                               return_value=False), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "listener_guard_effective",
                               side_effect=[False, True]), \
             mock.patch.object(dns_rescue.dns_runtime, "stage_listener_acl",
                               side_effect=lambda _cfg, scope, *_a, **_k:
                               guards.append(scope)), \
             mock.patch.object(dns_rescue.dns_runtime, "service_state",
                               return_value="inactive"), \
             mock.patch.object(dns_rescue.dns_runtime, "service_start") as start:
            state = dns_rescue.reconcile(self.cfg, self.pool, _locked=True)
        self.assertEqual(state["phase"], "recovering")
        self.assertEqual(guards, ["peer:10.77.0.9"])
        self.assertNotIn("all", guards)
        start.assert_called_once()

    def test_nodewide_preflight_recovery_uses_only_exact_canary_peer(self):
        operation = self.pool.begin_dns_operation(
            "node-scope-crash", "activate-node_wide_automatic",
            "cloudflare-proxy", "all", "auto", "node-preflight-crash",
            profile_class="all-present", generation="generation-node")
        for phase in ("staging", "started"):
            operation = self.pool.transition_dns_operation(operation["id"], phase)
        scope = dns_rescue._recovery_guard_scope(
            self.cfg, self.pool.dns_state(),
            self.pool.unfinished_dns_operations())
        self.assertEqual(scope, "peer:10.77.0.9")

    def test_deactivate_recovery_fallback_scope_never_authorizes_global_acl(self):
        with mock.patch.object(dns_rescue.dns_runtime, "firewall_attached",
                               return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "service_active",
                               return_value=False), \
             mock.patch.object(dns_rescue.dns_runtime, "deactivate_redirect",
                               side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                dns_rescue._deactivate_locked(
                    self.cfg, self.pool, "auto", "crash-with-unknown-scope")
        operation = self.pool.unfinished_dns_operations()[0]
        self.assertEqual(operation["scope"], "all")
        self.assertIsNone(json.loads(operation["snapshot_json"])[
            "authorized_guard_scope"])
        with mock.patch.object(dns_rescue.os, "name", "posix"), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "scrub_candidate_sidecar"), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "scrub_primary_test_bypass"), \
             mock.patch.object(dns_rescue.dns_runtime, "firewall_attached",
                               return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "deactivate_redirect",
                               side_effect=dns_runtime.DNSRuntimeError("unknown")), \
             mock.patch.object(dns_rescue.dns_runtime, "redirect_detached",
                               return_value=False), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "stage_listener_acl") as stage, \
             mock.patch.object(dns_rescue.dns_runtime, "service_start") as start:
            recovered = dns_rescue.reconcile(self.cfg, self.pool, _locked=True)
        self.assertEqual(recovered["phase"], "recovering")
        stage.assert_not_called()
        start.assert_not_called()

    def test_reconcile_terminals_crashed_deactivation_before_exit_resume(self):
        self.cfg = normalized("automatic_last_resort", True, True)
        self.pool.set_settings({"automat_state": "EMERGENCY",
                                "dns_incident_id": "dns-crash-exit",
                                "dns_recovery_exhausted": "1",
                                "dns_exit_resume": json.dumps({
                                    "resume_id": "resume-crash-exit",
                                    "incident_id": "dns-crash-exit", "scope": "all",
                                    "slot_id": "cloudflare-proxy",
                                    "active_kind": "node_wide_automatic",
                                    "profile_class": "all-present",
                                    "boot_id": "boot-test",
                                    "scope_identity": "scope-test",
                                    "attempt_seq": 0, "retry_monotonic": 0})})
        operation = self.pool.begin_dns_operation(
            "dns-crash-exit", "deactivate-node_wide_automatic",
            "cloudflare-proxy", "all", "auto", "deactivate-crash",
            generation="generation-test")
        for phase in ("staging", "started", "redirected", "verifying"):
            operation = self.pool.transition_dns_operation(operation["id"], phase)
        restored = dict(self.pool.dns_state(), phase="active_proxy",
                        incident_id="dns-crash-exit", active_scope="all",
                        active_slot="cloudflare-proxy",
                        active_kind="node_wide_automatic")
        with mock.patch.object(dns_rescue.os, "name", "posix"), \
             mock.patch.object(dns_rescue, "_boot_id", return_value="boot-test"), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "scrub_candidate_sidecar"), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "scrub_primary_test_bypass"), \
             mock.patch.object(dns_rescue.dns_runtime, "firewall_attached",
                               return_value=False), \
             mock.patch.object(dns_rescue.dns_runtime, "service_inactive",
                               return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "emergency_route_state",
                               return_value="ready"), \
             mock.patch.object(dns_rescue, "_activate_locked",
                               side_effect=self._resume_success(
                                   "dns_exit_resume", restored)) as activate:
            state = dns_rescue.reconcile(self.cfg, self.pool, _locked=True)
        self.assertEqual(state["active_scope"], "all")
        activate.assert_called_once()
        self.assertFalse(self.pool.unfinished_dns_operations())

    def test_unknown_service_state_counts_failure_without_immediate_failover(self):
        self.pool.set_dns_state(
            phase="active_isolated", incident_id="manual-test",
            active_scope="peer:10.77.0.9", active_slot="cloudflare-proxy",
            active_kind="isolated_manual", expires_at="2999-01-01 00:15:00",
            expires_monotonic=999999999.0, boot_id="boot-test",
            scope_identity="scope-test", client_path_last_ok=dns_rescue._now(),
            active_last_check="2000-01-01 00:00:00", active_failures=0)
        with mock.patch.object(dns_rescue, "_boot_id", return_value="boot-test"), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "wireguard_scope_identity_state",
                               return_value={"status": "valid",
                                             "identity": "scope-test"}), \
             mock.patch.object(dns_rescue.dns_runtime, "service_state",
                               return_value="unknown"), \
             mock.patch.object(dns_rescue, "probe_backend") as probe, \
             mock.patch.object(dns_rescue, "_failover_locked") as failover:
            result = dns_rescue.automatic_tick(
                self.cfg, self.pool, "OK", _locked=True)
        self.assertEqual(result["action"], "active")
        self.assertEqual(result["state"]["active_failures"], 1)
        probe.assert_not_called()
        failover.assert_not_called()

    def test_reconcile_does_not_bypass_backend_failure_threshold(self):
        self.pool.set_dns_state(
            phase="active_isolated", configured_mode="manual_canary", incident_id="manual-test",
            active_scope="peer:10.77.0.9", active_slot="cloudflare-proxy",
            active_kind="isolated_manual", activated_at="2999-01-01 00:00:00",
            expires_at="2999-01-01 00:15:00",
            expires_monotonic=time.monotonic() + 900.0,
            generation="generation-test", scope_identity="scope-test",
            boot_id="boot-test")
        with mock.patch.object(dns_rescue.os, "name", "posix"), \
             mock.patch.object(dns_rescue, "_boot_id", return_value="boot-test"), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "scrub_candidate_sidecar"), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "scrub_primary_test_bypass"), \
             mock.patch.object(dns_rescue.dns_runtime, "firewall_attached", return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "firewall_effective", return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "service_state", return_value="active"), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "wireguard_scope_identity_state",
                               return_value={"status": "valid",
                                             "identity": "scope-test"}), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "deactivate_redirect") as detach, \
             mock.patch.object(dns_rescue, "probe_backend",
                               side_effect=AssertionError("reconcile must not health-probe")):
            state = dns_rescue.reconcile(self.cfg, self.pool, _locked=True)
        self.assertEqual(state["active_scope"], "peer:10.77.0.9")
        detach.assert_not_called()

    def test_reconcile_preserves_proven_active_rescue_after_config_gate_closes(self):
        self.cfg["dns_rescue"]["mode"] = "disabled"
        self.pool.set_dns_state(
            phase="active_isolated", configured_mode="manual_canary",
            incident_id="manual-test", active_scope="peer:10.77.0.9",
            active_slot="cloudflare-proxy", active_kind="isolated_manual",
            expires_at="2999-01-01 00:15:00",
            expires_monotonic=time.monotonic() + 900.0,
            generation="generation-test", scope_identity="scope-test",
            boot_id="boot-test")
        with mock.patch.object(dns_rescue.os, "name", "posix"), \
             mock.patch.object(dns_rescue, "_boot_id", return_value="boot-test"), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "scrub_candidate_sidecar"), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "scrub_primary_test_bypass"), \
             mock.patch.object(dns_rescue.dns_runtime, "firewall_attached", return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "firewall_effective", return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "service_state", return_value="active"), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "wireguard_scope_identity_state",
                               return_value={"status": "valid",
                                             "identity": "scope-test"}), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "deactivate_redirect") as detach:
            state = dns_rescue.reconcile(self.cfg, self.pool, _locked=True)
        self.assertEqual(state["active_scope"], "peer:10.77.0.9")
        detach.assert_not_called()

    def test_reconcile_unknown_service_inspection_preserves_proven_nat(self):
        self.pool.set_dns_state(
            phase="active_isolated", configured_mode="manual_canary",
            incident_id="manual-test", active_scope="peer:10.77.0.9",
            active_slot="cloudflare-proxy", active_kind="isolated_manual",
            expires_at="2999-01-01 00:15:00", expires_monotonic=999999999.0,
            generation="generation-test", scope_identity="scope-test",
            boot_id="boot-test")
        with mock.patch.object(dns_rescue.os, "name", "posix"), \
             mock.patch.object(dns_rescue, "_boot_id", return_value="boot-test"), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "scrub_candidate_sidecar"), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "scrub_primary_test_bypass"), \
             mock.patch.object(dns_rescue.dns_runtime, "firewall_attached",
                               return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "firewall_effective",
                               return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "service_state",
                               return_value="unknown"), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "wireguard_scope_identity_state",
                               return_value={"status": "valid",
                                             "identity": "scope-test"}), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "deactivate_redirect") as detach:
            state = dns_rescue.reconcile(self.cfg, self.pool, _locked=True)
        self.assertEqual(state["phase"], "active_isolated")
        self.assertEqual(state["last_error"], "service-inspection-unknown")
        detach.assert_not_called()

    def test_candidate_series_uses_one_shared_activation_deadline(self):
        self.cfg = normalized("automatic_last_resort", True, True)
        deadlines = []

        def reject(*_args, **kwargs):
            deadlines.append(kwargs.get("deadline_monotonic"))
            return {"ok": False, "action": "failed"}

        with mock.patch.object(dns_rescue.time, "monotonic",
                               side_effect=[100.0, 101.0, 102.0, 103.0, 104.0]), \
             mock.patch.object(dns_rescue, "_activate_locked", side_effect=reject):
            result = dns_rescue._activate_series_locked(
                self.cfg, self.pool, "dns-shared-deadline")
        self.assertEqual(result["action"], "candidates-exhausted")
        self.assertEqual(len(deadlines), 4)
        self.assertEqual(set(deadlines), {130.0})

    def test_automatic_failover_skips_expired_candidates(self):
        self.cfg = normalized("automatic_last_resort", True, True)
        self.cfg["dns_rescue"]["candidates"][1]["not_after"] = "2000-01-01T00:00:00Z"
        slots = dns_rescue._failover_slots(
            self.cfg, self.cfg["dns_rescue"]["candidates"][0]["id"], set(),
            require_fresh=True)
        self.assertNotIn(self.cfg["dns_rescue"]["candidates"][1]["id"],
                         [item["id"] for item in slots])

    def test_isolated_failover_preserves_original_monotonic_deadline(self):
        state = self.pool.set_dns_state(
            phase="active_isolated", incident_id="manual-test",
            active_scope="peer:10.77.0.9", active_slot="cloudflare-proxy",
            active_kind="isolated_manual", expires_at="2999-01-01 00:15:00",
            expires_monotonic=222.0, boot_id="boot-test",
            scope_identity="scope-test")
        good = {"ok": True, "results": [{"ok": True}, {"ok": True}]}
        chosen = next(item for item in self.cfg["dns_rescue"]["candidates"]
                      if item["id"] == "google-proxy")
        with mock.patch.object(dns_rescue.os, "name", "posix"), \
             mock.patch.object(dns_rescue, "_boot_id", return_value="boot-test"), \
             mock.patch.object(dns_rescue.dns_runtime, "peer_canary_runner_ready",
                               return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "wireguard_scope_ready",
                               return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "wireguard_scope_identity",
                               return_value="scope-test"), \
             mock.patch.object(dns_rescue.dns_runtime, "emergency_route_ready",
                               return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "candidate_sidecar_preflight_proven", return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "stage_config"), \
             mock.patch.object(dns_rescue.dns_runtime, "service_start"), \
             mock.patch.object(dns_rescue.dns_runtime, "firewall_effective",
                               return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "client_roundtrip_proven",
                               return_value=True), \
             mock.patch.object(dns_rescue, "probe_backend", return_value=good):
            result = dns_rescue._switch_active_candidate_locked(
                self.cfg, self.pool, state, chosen, "wg-ip",
                dns_rescue.time.monotonic() + 30, print)
        self.assertEqual(result["action"], "backend-failover")
        self.assertEqual(result["state"]["expires_monotonic"], 222.0)
        self.assertEqual(result["state"]["expires_at"], "2999-01-01 00:15:00")
        self.assertEqual(result["state"]["boot_id"], "boot-test")

    def test_nodewide_preflight_failure_never_broadens_listener_guard(self):
        self.pool.set_settings({"automat_state": "EMERGENCY",
                                "emergency_manual": "1",
                                "manual_emergency_ref": "manual-ref"})
        guards = []
        good = {"ok": True, "results": [{"ok": True}, {"ok": True}]}
        with mock.patch.object(dns_rescue.os, "name", "posix"), \
             mock.patch.object(dns_rescue, "_boot_id", return_value="boot-test"), \
             mock.patch.object(dns_rescue.dns_runtime, "peer_canary_runner_ready",
                               return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "wireguard_scope_ready",
                               return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "wireguard_scope_identity",
                               return_value="scope-test"), \
             mock.patch.object(dns_rescue.dns_runtime, "emergency_route_ready",
                               return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "firewall_attached",
                               return_value=False), \
             mock.patch.object(dns_rescue.dns_runtime, "service_active",
                               return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "stage_config"), \
             mock.patch.object(dns_rescue.dns_runtime, "stage_listener_acl",
                               side_effect=lambda _cfg, scope, **_kw: guards.append(scope)), \
             mock.patch.object(dns_rescue.dns_runtime, "service_start"), \
             mock.patch.object(dns_rescue.dns_runtime, "activate_firewall"), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "client_candidate_preflight_proven", return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "deactivate_redirect",
                               side_effect=dns_runtime.DNSRuntimeError("partial")), \
             mock.patch.object(dns_rescue.dns_runtime, "redirect_detached",
                               return_value=False), \
             mock.patch.object(dns_rescue.dns_runtime, "listener_guard_effective",
                               return_value=False), \
             mock.patch.object(dns_rescue, "probe_backend", return_value=good):
            result = dns_rescue._activate_locked(
                self.cfg, self.pool, "all", "cloudflare-proxy", "user", False,
                print)
        self.assertEqual(result["action"], "fail-open-blocked")
        self.assertEqual(result["state"]["active_scope"], "peer:10.77.0.9")
        self.assertTrue(guards)
        self.assertNotIn("all", guards)

    def test_nodewide_config_stage_failure_recovers_only_exact_canary_guard(self):
        self.pool.set_settings({"automat_state": "EMERGENCY",
                                "emergency_manual": "1",
                                "manual_emergency_ref": "manual-ref"})
        guards = []
        with mock.patch.object(dns_rescue.os, "name", "posix"), \
             mock.patch.object(dns_rescue, "_boot_id", return_value="boot-test"), \
             mock.patch.object(dns_rescue.dns_runtime, "peer_canary_runner_ready",
                               return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "wireguard_scope_ready",
                               return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "wireguard_scope_identity",
                               return_value="scope-test"), \
             mock.patch.object(dns_rescue.dns_runtime, "emergency_route_ready",
                               return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "firewall_attached",
                               return_value=False), \
             mock.patch.object(dns_rescue.dns_runtime, "service_active",
                               return_value=False), \
             mock.patch.object(dns_rescue.dns_runtime, "stage_config",
                               side_effect=dns_runtime.DNSRuntimeError("stage failed")), \
             mock.patch.object(dns_rescue.dns_runtime, "deactivate_redirect",
                               side_effect=dns_runtime.DNSRuntimeError("unknown")), \
             mock.patch.object(dns_rescue.dns_runtime, "redirect_detached",
                               return_value=False), \
             mock.patch.object(dns_rescue.dns_runtime, "listener_guard_effective",
                               return_value=False), \
             mock.patch.object(dns_rescue.dns_runtime, "stage_listener_acl",
                               side_effect=lambda _cfg, scope, *_a, **_k:
                               guards.append(scope)), \
             mock.patch.object(dns_rescue.dns_runtime, "service_start"):
            result = dns_rescue._activate_locked(
                self.cfg, self.pool, "all", "cloudflare-proxy", "user", False,
                print)
        self.assertEqual(result["action"], "fail-open-blocked")
        self.assertEqual(guards, ["peer:10.77.0.9"])
        self.assertEqual(result["state"]["active_scope"], "peer:10.77.0.9")

    def test_isolated_rescue_is_removed_when_state_leaves_normal(self):
        state = self.pool.set_dns_state(
            phase="active_isolated", incident_id="manual-test",
            active_scope="peer:10.77.0.9", active_slot="cloudflare-proxy",
            active_kind="isolated_manual", expires_at="2999-01-01 00:15:00",
            expires_monotonic=999999999.0, boot_id="boot-test",
            scope_identity="scope-test")
        stopped = {"ok": True, "action": "deactivated", "state": state}
        with mock.patch.object(dns_rescue, "_deactivate_locked",
                               return_value=stopped) as deactivate:
            result = dns_rescue._automatic_tick_locked(
                self.cfg, self.pool, "EMERGENCY", False, print)
        self.assertEqual(result["action"], "deactivated")
        self.assertEqual(deactivate.call_args.args[3], "isolated-left-normal-state")

    def test_reconcile_restores_nodewide_rescue_after_reboot(self):
        self.cfg = normalized("automatic_last_resort", True, True)
        self.pool.set_settings({"automat_state": "EMERGENCY",
                                "emergency_manual": None,
                                "dns_recovery_exhausted": "1",
                                "dns_incident_id": "dns-boot"})
        self._seed_nodewide_committed()

        def restore(_cfg, pool, _scope, slot_id, *_args, **kwargs):
            restored = pool.set_dns_state(
                phase="active_proxy", active_scope="all", active_slot=slot_id,
                active_kind="node_wide_automatic", incident_id="dns-boot",
                scope_identity="scope-test", boot_id="boot-new",
                backend_last_ok=dns_rescue._now(),
                client_path_last_ok=dns_rescue._now())
            return {"ok": True, "action": "activated", "state": restored}

        with mock.patch.object(dns_rescue.os, "name", "posix"), \
             mock.patch.object(dns_rescue, "_boot_id", return_value="boot-new"), \
             mock.patch.object(dns_rescue, "_physical", return_value=False), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "scrub_candidate_sidecar"), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "scrub_primary_test_bypass"), \
             mock.patch.object(dns_rescue.dns_runtime, "firewall_attached",
                               return_value=False), \
             mock.patch.object(dns_rescue.dns_runtime, "service_inactive",
                               return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "wireguard_scope_identity_state",
                               return_value={"status": "valid",
                                             "identity": "scope-test"}), \
             mock.patch.object(dns_rescue, "_activate_locked",
                               side_effect=lambda *args, **kwargs: (
                                   self.pool.set_setting("dns_boot_resume", None),
                                   restore(*args, **kwargs))[1]) as activate:
            state = dns_rescue.reconcile(self.cfg, self.pool, _locked=True)
        self.assertEqual(state["boot_id"], "boot-new")
        self.assertEqual(state["active_scope"], "all")
        self.assertIsNone(self.pool.get_setting("dns_boot_resume"))
        self.assertTrue(activate.call_args.kwargs["continuation"])
        self.assertEqual(activate.call_args.kwargs["expected_scope_identity"],
                         "scope-test")

    def test_reboot_during_failover_preserves_nodewide_resume_intent(self):
        self.cfg = normalized("automatic_last_resort", True, True)
        self.pool.set_settings({"automat_state": "EMERGENCY",
                                "emergency_manual": None,
                                "dns_recovery_exhausted": "1",
                                "dns_incident_id": "dns-boot"})
        self._seed_nodewide_committed()
        interrupted = self.pool.begin_dns_operation(
            "dns-boot", "activate-node_wide_automatic", "google-proxy",
            "all", "auto", "failover-before-reboot",
            profile_class="all-present", generation="generation-next")
        self.pool.transition_dns_operation(interrupted["id"], "staging")
        common = (
            mock.patch.object(dns_rescue.os, "name", "posix"),
            mock.patch.object(dns_rescue, "_boot_id", return_value="boot-new"),
            mock.patch.object(dns_rescue, "_physical", return_value=False),
            mock.patch.object(dns_rescue.dns_runtime,
                              "scrub_candidate_sidecar"),
            mock.patch.object(dns_rescue.dns_runtime,
                              "scrub_primary_test_bypass"),
            mock.patch.object(dns_rescue.dns_runtime, "firewall_attached",
                              return_value=False),
            mock.patch.object(dns_rescue.dns_runtime, "service_inactive",
                              return_value=True),
            mock.patch.object(dns_rescue.dns_runtime,
                              "wireguard_scope_identity_state",
                              return_value={"status": "valid",
                                            "identity": "scope-test"}),
        )
        with common[0], common[1], common[2], common[3], common[4], \
                common[5], common[6], common[7]:
            first = dns_rescue.reconcile(self.cfg, self.pool, _locked=True)
        self.assertEqual(first["phase"], "failed")
        self.assertIsNotNone(self.pool.get_setting("dns_boot_resume"))
        self.assertFalse(self.pool.unfinished_dns_operations())

        restored = dict(self.pool.dns_state(), phase="active_proxy",
                        incident_id="dns-boot", active_scope="all",
                        active_slot="cloudflare-proxy",
                        active_kind="node_wide_automatic", boot_id="boot-new")
        with common[0], common[1], common[2], common[3], common[4], \
                common[5], common[6], common[7], \
             mock.patch.object(dns_rescue, "_activate_locked",
                               side_effect=self._resume_success(
                                   "dns_boot_resume", restored)) as activate:
            second = dns_rescue.reconcile(self.cfg, self.pool, _locked=True)
        self.assertEqual(second["active_scope"], "all")
        activate.assert_called_once()

    def test_status_never_exposes_manual_emergency_reference(self):
        self.pool.set_dns_state(manual_emergency_ref="opaque-reference")
        with mock.patch.object(dns_rescue, "_physical", return_value=False):
            public = dns_rescue.status(self.cfg, self.pool)
        self.assertNotIn("manual_emergency_ref", public["state"])

    def test_expired_candidate_without_fresh_replacement_preserves_runtime(self):
        for candidate in self.cfg["dns_rescue"]["candidates"]:
            candidate["not_after"] = "2000-01-01T00:00:00Z"
        self.pool.set_dns_state(
            phase="active_isolated", incident_id="manual-test",
            active_scope="peer:10.77.0.9", active_slot="cloudflare-proxy",
            active_kind="isolated_manual", expires_at="2999-01-01 00:15:00",
            expires_monotonic=999999999.0, boot_id="boot-test",
            scope_identity="scope-test", backend_last_ok=dns_rescue._now(),
            client_path_last_ok=dns_rescue._now())
        with mock.patch.object(dns_rescue, "_boot_id", return_value="boot-test"), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "wireguard_scope_identity_state",
                               return_value={"status": "valid",
                                             "identity": "scope-test"}), \
             mock.patch.object(dns_rescue.dns_runtime, "service_state",
                               return_value="active"), \
             mock.patch.object(dns_rescue.dns_runtime, "firewall_effective", return_value=True), \
             mock.patch.object(dns_rescue, "_deactivate_locked") as deactivate:
            result = dns_rescue.automatic_tick(
                self.cfg, self.pool, "OK", _locked=True)
        self.assertEqual(result["action"], "active-evidence-expired")
        deactivate.assert_not_called()

    def test_expired_candidate_with_stale_runtime_proof_is_detached(self):
        for candidate in self.cfg["dns_rescue"]["candidates"]:
            candidate["not_after"] = "2000-01-01T00:00:00Z"
        self.pool.set_dns_state(
            phase="active_isolated", incident_id="manual-test",
            active_scope="peer:10.77.0.9", active_slot="cloudflare-proxy",
            active_kind="isolated_manual", expires_at="2999-01-01 00:15:00",
            expires_monotonic=999999999.0, boot_id="boot-test",
            scope_identity="scope-test", backend_last_ok="2000-01-01 00:00:00",
            client_path_last_ok="2000-01-01 00:00:00")
        idle = {"ok": True, "action": "deactivated", "state": self.pool.dns_state()}
        with mock.patch.object(dns_rescue, "_boot_id", return_value="boot-test"), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "wireguard_scope_identity_state",
                               return_value={"status": "valid",
                                             "identity": "scope-test"}), \
             mock.patch.object(dns_rescue.dns_runtime, "service_state",
                               return_value="inactive"), \
             mock.patch.object(dns_rescue, "_deactivate_locked",
                               return_value=idle) as deactivate:
            result = dns_rescue.automatic_tick(
                self.cfg, self.pool, "OK", _locked=True)
        self.assertEqual(result["action"], "all-candidates-unhealthy")
        deactivate.assert_called_once()

    def test_inactive_listener_detaches_before_any_successor_attempt(self):
        state = self._seed_nodewide_committed(boot_id="boot-test")
        self.pool.set_dns_state(active_last_check="2000-01-01 00:00:00")
        order = []

        def stop(*_args, **_kwargs):
            order.append("detach")
            idle = self.pool.set_dns_state(
                phase="idle", active_scope=None, active_slot=None,
                active_kind=None, boot_id=None, scope_identity=None)
            return {"ok": True, "action": "deactivated", "state": idle}

        def reject(*_args, **_kwargs):
            order.append("candidate")
            return {"ok": False, "action": "rolled-back",
                    "state": self.pool.dns_state()}

        with mock.patch.object(dns_rescue, "_boot_id", return_value="boot-test"), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "wireguard_scope_identity_state",
                               return_value={"status": "valid",
                                             "identity": "scope-test"}), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "emergency_route_state", return_value="ready"), \
             mock.patch.object(dns_rescue.dns_runtime, "service_state",
                               return_value="inactive"), \
             mock.patch.object(dns_rescue, "_deactivate_locked",
                               side_effect=stop) as detach, \
             mock.patch.object(dns_rescue, "_activate_locked",
                               side_effect=reject), \
             mock.patch.object(dns_rescue, "_switch_active_candidate_locked") as live_switch, \
             mock.patch.object(dns_rescue.dns_runtime, "firewall_attached",
                               return_value=False):
            result = dns_rescue._automatic_tick_locked(
                self.cfg, self.pool, "EMERGENCY", False, print)
        self.assertEqual(result["action"], "all-candidates-unhealthy")
        self.assertGreater(len(order), 1)
        self.assertEqual(order[0], "detach")
        self.assertTrue(all(item == "candidate" for item in order[1:]))
        detach.assert_called_once()
        live_switch.assert_not_called()

    def test_isolated_future_ttl_is_not_torn_down_on_first_tick(self):
        self.pool.set_dns_state(
            phase="active_isolated", incident_id="manual-test",
            active_scope="peer:10.77.0.9", active_slot="cloudflare-proxy",
            active_kind="isolated_manual", expires_at="2999-01-01 00:15:00",
            expires_monotonic=999999999.0, boot_id="boot-test",
            scope_identity="scope-test", client_path_last_ok=dns_rescue._now(),
            active_last_check="2000-01-01 00:00:00")
        with mock.patch.object(dns_rescue.dns_runtime, "service_active", return_value=True), \
             mock.patch.object(dns_rescue, "_boot_id", return_value="boot-test"), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "wireguard_scope_identity_state",
                               return_value={"status": "valid",
                                             "identity": "scope-test"}), \
             mock.patch.object(dns_rescue.dns_runtime, "emergency_route_ready",
                               return_value=True), \
             mock.patch.object(dns_rescue, "probe_backend",
                               return_value={"ok": True, "results": []}), \
             mock.patch.object(dns_rescue, "_deactivate_locked") as deactivate:
            result = dns_rescue.automatic_tick(
                self.cfg, self.pool, "OK", _locked=True)
        self.assertEqual(result["action"], "active")
        deactivate.assert_not_called()

    def test_primary_return_probe_respects_interval(self):
        self.cfg = normalized("automatic_last_resort", True, True)
        self.pool.set_dns_state(
            phase="active_proxy", incident_id="dns-test", active_scope="all",
            active_slot="cloudflare-proxy", active_kind="node_wide_automatic",
            active_last_check="2000-01-01 00:00:00", scope_identity="scope-test",
            client_path_last_ok=dns_rescue._now(), boot_id="boot-test",
            return_last_check=dns_rescue._now())
        with mock.patch.object(dns_rescue.dns_runtime, "service_active", return_value=True), \
             mock.patch.object(dns_rescue, "_boot_id", return_value="boot-test"), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "wireguard_scope_identity_state",
                               return_value={"status": "valid",
                                             "identity": "scope-test"}), \
             mock.patch.object(dns_rescue.dns_runtime, "emergency_route_state",
                               return_value="ready"), \
             mock.patch.object(dns_rescue, "probe_backend",
                               return_value={"ok": True, "results": []}), \
             mock.patch.object(dns_rescue, "_primary_dns_failure") as primary:
            result = dns_rescue.automatic_tick(
                self.cfg, self.pool, "EMERGENCY", _locked=True)
        self.assertEqual(result["action"], "active")
        primary.assert_not_called()

    def test_sticky_manual_emergency_takes_over_active_automatic_rescue(self):
        self.cfg = normalized("automatic_last_resort", True, True)
        self.pool.set_settings({"emergency_manual": "1",
                                "manual_emergency_ref": "manual-ref"})
        self.pool.set_dns_state(
            phase="active_proxy", incident_id="dns-test", active_scope="all",
            active_slot="cloudflare-proxy", active_kind="node_wide_automatic",
            active_last_check="2000-01-01 00:00:00", scope_identity="scope-test",
            client_path_last_ok=dns_rescue._now(), boot_id="boot-test")
        with mock.patch.object(dns_rescue.dns_runtime, "service_active", return_value=True), \
             mock.patch.object(dns_rescue, "_boot_id", return_value="boot-test"), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "wireguard_scope_identity_state",
                               return_value={"status": "valid",
                                             "identity": "scope-test"}), \
             mock.patch.object(dns_rescue.dns_runtime, "emergency_route_state",
                               return_value="ready"), \
             mock.patch.object(dns_rescue, "probe_backend",
                               return_value={"ok": True, "results": []}), \
             mock.patch.object(dns_rescue, "_primary_dns_failure") as primary:
            result = dns_rescue.automatic_tick(
                self.cfg, self.pool, "EMERGENCY", manual_emergency=True,
                _locked=True)
        self.assertEqual(result["action"], "active")
        self.assertEqual(result["state"]["active_kind"], "node_wide_manual")
        self.assertEqual(result["state"]["manual_emergency_ref"], "manual-ref")
        primary.assert_not_called()

    def test_isolated_canary_requires_normal_unfrozen_state(self):
        self.pool.set_setting("automat_state", "DEGRADED")
        with mock.patch.object(dns_rescue.os, "name", "posix"), \
             mock.patch.object(dns_rescue.dns_runtime, "peer_canary_runner_ready",
                               return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "wireguard_scope_ready",
                               return_value=True):
            with self.assertRaisesRegex(dns_rescue.DNSRescueError, "NORMAL"):
                dns_rescue._validate_scope_locked(
                    self.cfg, self.pool, "peer:10.77.0.9", False,
                    profile_class="wg-ip")

    def test_failed_emergency_exit_has_durable_dns_compensation(self):
        self.pool.set_setting("automat_state", "EMERGENCY")
        self.pool.set_dns_state(
            phase="active_isolated", configured_mode="manual_canary",
            incident_id="manual-test", active_scope="peer:10.77.0.9",
            active_slot="cloudflare-proxy", active_kind="isolated_manual",
            expires_at="2999-01-01 00:15:00", expires_monotonic=999999999.0,
            boot_id="boot-test", scope_identity="scope-test",
            generation="generation-test",
            backend_last_ok=dns_rescue._now(),
            client_path_last_ok=dns_rescue._now())

        def fake_deactivate(cfg, pool, actor, reason):
            state = pool.set_dns_state(
                phase="idle", active_scope=None, active_slot=None, active_kind=None)
            return {"ok": True, "action": "deactivated", "state": state}

        with mock.patch.object(dns_rescue.os, "name", "posix"), \
             mock.patch.object(dns_rescue, "_boot_id", return_value="boot-test"), \
             mock.patch.object(dns_rescue, "_pre_exit_physical_state",
                               return_value="ready"), \
             mock.patch.object(dns_rescue, "_active_profile_class",
                               return_value="wg-ip"), \
             mock.patch.object(dns_rescue.dns_runtime, "firewall_attached", return_value=False), \
             mock.patch.object(dns_rescue, "_deactivate_locked", side_effect=fake_deactivate):
            prepared = dns_rescue.prepare_for_emergency_exit(
                self.cfg, self.pool, _locked=True)
        self.assertTrue(prepared["resume_pending"])
        self.assertTrue(self.pool.get_setting("dns_exit_resume"))

        resumed_state = dict(
            self.pool.dns_state(), phase="active_isolated",
            active_scope="peer:10.77.0.9", active_slot="cloudflare-proxy",
            active_kind="isolated_manual")
        self.pool.set_setting("automat_state", "OK")
        with mock.patch.object(dns_rescue.os, "name", "posix"), \
             mock.patch.object(dns_rescue, "_boot_id", return_value="boot-test"), \
             mock.patch.object(dns_rescue.dns_runtime, "emergency_route_state",
                               return_value="ready"), \
             mock.patch.object(dns_rescue, "_activate_locked",
                               side_effect=self._resume_success(
                                   "dns_exit_resume", resumed_state)) as activate:
            result = dns_rescue.resume_after_emergency_exit_failure(
                self.cfg, self.pool, _locked=True)
        self.assertTrue(result["ok"])
        self.assertIsNone(self.pool.get_setting("dns_exit_resume"))
        self.assertTrue(activate.call_args.kwargs["idempotency_key"].startswith(
            "dns-exit-resume:"))
        self.assertEqual(activate.call_args.kwargs["resume_expires_at"],
                         "2999-01-01 00:15:00")
        self.assertEqual(activate.call_args.kwargs["resume_expires_monotonic"],
                         999999999.0)
        self.assertEqual(activate.call_args.kwargs["expected_scope_identity"],
                         "scope-test")
        self.assertTrue(activate.call_args.kwargs["continuation"])

    def test_expired_isolated_exit_compensation_never_extends_ttl(self):
        self.pool.set_setting("automat_state", "EMERGENCY")
        self.pool.set_setting("dns_exit_resume", json.dumps({
            "resume_id": "resume-1", "incident_id": "manual-test",
            "scope": "peer:10.77.0.9", "slot_id": "cloudflare-proxy",
            "active_kind": "isolated_manual", "profile_class": "wg-ip",
            "expires_at": "2000-01-01 00:00:00", "expires_monotonic": 1.0,
            "boot_id": "boot-test", "scope_identity": "scope-test"}))
        with mock.patch.object(dns_rescue.dns_runtime, "emergency_route_state",
                               return_value="ready"), \
             mock.patch.object(dns_rescue, "_boot_id", return_value="boot-test"), \
             mock.patch.object(dns_rescue, "_activate_locked") as activate:
            result = dns_rescue._resume_after_exit_failure_locked(
                self.cfg, self.pool)
        self.assertEqual(result["action"], "resume-expired")
        self.assertIsNone(self.pool.get_setting("dns_exit_resume"))
        activate.assert_not_called()

    def test_nodewide_exit_compensation_adopts_boot_resume_after_reboot(self):
        self.cfg = normalized("automatic_last_resort", True, True)
        self.pool.set_settings({"automat_state": "EMERGENCY",
                                "dns_incident_id": "dns-cross-boot",
                                "dns_recovery_exhausted": "1",
                                "dns_exit_resume": json.dumps({
                                    "resume_id": "resume-cross-boot",
                                    "incident_id": "dns-cross-boot", "scope": "all",
                                    "slot_id": "cloudflare-proxy",
                                    "active_kind": "node_wide_automatic",
                                    "profile_class": "all-present",
                                    "boot_id": "boot-old",
                                    "scope_identity": "scope-test",
                                    "attempt_seq": 0, "retry_monotonic": 0})})
        restored = dict(self.pool.dns_state(), phase="active_proxy",
                        incident_id="dns-cross-boot", active_scope="all",
                        active_slot="cloudflare-proxy",
                        active_kind="node_wide_automatic", boot_id="boot-new")
        with mock.patch.object(dns_rescue, "_boot_id", return_value="boot-new"), \
             mock.patch.object(dns_rescue, "_physical", return_value=False), \
             mock.patch.object(dns_rescue.dns_runtime, "emergency_route_state",
                               return_value="ready"), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "wireguard_scope_identity_state",
                               return_value={"status": "valid",
                                             "identity": "scope-test"}), \
             mock.patch.object(dns_rescue.dns_runtime, "service_inactive",
                               return_value=True), \
             mock.patch.object(dns_rescue, "_activate_locked",
                               side_effect=self._resume_success(
                                   "dns_boot_resume", restored)) as activate:
            result = dns_rescue._resume_after_exit_failure_locked(
                self.cfg, self.pool)
        self.assertEqual(result["action"], "boot-restored")
        self.assertIsNone(self.pool.get_setting("dns_exit_resume"))
        self.assertIsNone(self.pool.get_setting("dns_boot_resume"))
        activate.assert_called_once()

    def test_failed_exit_teardown_keeps_compensation_descriptor(self):
        self.pool.set_dns_state(
            phase="active_isolated", configured_mode="manual_canary",
            incident_id="manual-test", active_scope="peer:10.77.0.9",
            active_slot="cloudflare-proxy", active_kind="isolated_manual",
            expires_at="2999-01-01 00:15:00", expires_monotonic=999999999.0,
            boot_id="boot-test", scope_identity="scope-test",
            generation="generation-test",
            backend_last_ok=dns_rescue._now(),
            client_path_last_ok=dns_rescue._now())
        failed = {"ok": False, "action": "fail-open-blocked",
                  "state": self.pool.dns_state()}
        with mock.patch.object(dns_rescue.os, "name", "posix"), \
             mock.patch.object(dns_rescue, "_pre_exit_physical_state",
                               return_value="ready"), \
             mock.patch.object(dns_rescue, "_active_profile_class",
                               return_value="wg-ip"), \
             mock.patch.object(dns_rescue.dns_runtime, "firewall_attached",
                               return_value=True), \
             mock.patch.object(dns_rescue, "_deactivate_locked",
                               return_value=failed):
            result = dns_rescue.prepare_for_emergency_exit(
                self.cfg, self.pool, _locked=True)
        self.assertFalse(result["ok"])
        self.assertTrue(result["resume_pending"])
        resume = json.loads(self.pool.get_setting("dns_exit_resume"))
        self.assertEqual(resume["slot_id"], "cloudflare-proxy")
        self.assertEqual(resume["attempt_seq"], 0)

    def test_exit_compensation_uses_fresh_key_and_fails_over(self):
        self.pool.set_setting("automat_state", "OK")
        self.pool.set_setting("dns_exit_resume", json.dumps({
            "resume_id": "resume-1", "incident_id": "manual-test",
            "scope": "peer:10.77.0.9", "slot_id": "cloudflare-proxy",
            "active_kind": "isolated_manual", "profile_class": "wg-ip",
            "expires_at": "2999-01-01 00:15:00",
            "expires_monotonic": 999999999.0, "boot_id": "boot-test",
            "scope_identity": "scope-test", "attempt_seq": 2,
            "retry_monotonic": 0}))
        activated = dict(self.pool.dns_state(), phase="active_isolated",
                         active_scope="peer:10.77.0.9",
                         active_slot="google-proxy",
                         active_kind="isolated_manual")
        results = [
            {"ok": False, "action": "rolled-back", "state": self.pool.dns_state()},
            {"ok": True, "action": "activated", "state": activated},
        ]
        complete = self._resume_success("dns_exit_resume", activated)

        def activate_result(*args, **kwargs):
            if activate_result.calls == 0:
                activate_result.calls += 1
                return results[0]
            return complete(*args, **kwargs)
        activate_result.calls = 0

        with mock.patch.object(dns_rescue, "_boot_id", return_value="boot-test"), \
             mock.patch.object(dns_rescue.dns_runtime, "emergency_route_state",
                               return_value="ready"), \
             mock.patch.object(dns_rescue, "_activate_locked",
                               side_effect=activate_result) as activate:
            result = dns_rescue._resume_after_exit_failure_locked(
                self.cfg, self.pool)
        self.assertTrue(result["ok"])
        self.assertEqual(activate.call_count, 2)
        first = activate.call_args_list[0].kwargs
        second = activate.call_args_list[1].kwargs
        self.assertNotEqual(first["idempotency_key"], second["idempotency_key"])
        self.assertIn(":2:0", first["idempotency_key"])
        self.assertIn(":2:1", second["idempotency_key"])
        self.assertEqual(second["resume_expires_at"], "2999-01-01 00:15:00")
        self.assertEqual(second["resume_expires_monotonic"], 999999999.0)
        self.assertEqual(second["expected_scope_identity"], "scope-test")
        self.assertIsNone(self.pool.get_setting("dns_exit_resume"))

    def test_nodewide_manual_exit_resume_survives_closed_config_gate(self):
        self.cfg["dns_rescue"].update(
            mode="disabled", owner_approved=False, automatic_ready=False)
        self.pool.set_settings({"automat_state": "EMERGENCY",
                                "emergency_manual": "1",
                                "manual_emergency_ref": "manual-ref",
                                "dns_exit_resume": json.dumps({
                                    "resume_id": "resume-manual",
                                    "incident_id": "manual-test", "scope": "all",
                                    "slot_id": "cloudflare-proxy",
                                    "active_kind": "node_wide_manual",
                                    "profile_class": "all-present",
                                    "boot_id": "boot-test",
                                    "scope_identity": "scope-test",
                                    "manual_emergency_ref": "manual-ref",
                                    "attempt_seq": 0, "retry_monotonic": 0})})
        restored = dict(self.pool.dns_state(), phase="active_proxy",
                        active_scope="all", active_slot="cloudflare-proxy",
                        active_kind="node_wide_manual",
                        manual_emergency_ref="manual-ref")
        with mock.patch.object(dns_rescue, "_boot_id", return_value="boot-test"), \
             mock.patch.object(dns_rescue.dns_runtime, "emergency_route_state",
                               return_value="ready"), \
             mock.patch.object(dns_rescue, "_activate_locked",
                               side_effect=self._resume_success(
                                   "dns_exit_resume", restored)) as activate:
            result = dns_rescue._resume_after_exit_failure_locked(
                self.cfg, self.pool)
        self.assertTrue(result["ok"])
        self.assertTrue(activate.call_args.kwargs["continuation"])
        self.assertEqual(activate.call_args.kwargs[
            "expected_manual_emergency_ref"], "manual-ref")
        self.assertIsNone(self.pool.get_setting("dns_exit_resume"))

    def test_exit_compensation_exhaustion_is_durable_and_backed_off(self):
        self.pool.set_settings({"automat_state": "EMERGENCY",
                                "dns_incident_id": "manual-test",
                                "dns_recovery_exhausted": "1"})
        self.pool.set_setting("dns_exit_resume", json.dumps({
            "resume_id": "resume-1", "incident_id": "manual-test",
            "scope": "all", "slot_id": "cloudflare-proxy",
            "active_kind": "node_wide_automatic", "profile_class": "all-present",
            "boot_id": "boot-test", "scope_identity": "scope-test",
            "attempt_seq": 0, "retry_monotonic": 0}))
        failed = {"ok": False, "action": "rolled-back",
                  "state": self.pool.dns_state()}
        with mock.patch.object(dns_rescue, "_boot_id", return_value="boot-test"), \
             mock.patch.object(dns_rescue.dns_runtime, "emergency_route_state",
                               return_value="ready"), \
             mock.patch.object(dns_rescue, "_activate_locked",
                               return_value=failed) as activate:
            result = dns_rescue._resume_after_exit_failure_locked(
                self.cfg, self.pool)
        self.assertEqual(result["action"], "resume-retry-pending")
        self.assertEqual(activate.call_count, 4)
        resume = json.loads(self.pool.get_setting("dns_exit_resume"))
        self.assertEqual(resume["attempt_seq"], 1)
        self.assertGreater(resume["retry_monotonic"], 0)

    def test_exit_compensation_stops_after_bounded_rounds(self):
        self.pool.set_settings({"automat_state": "EMERGENCY",
                                "dns_incident_id": "dns-bounded",
                                "dns_recovery_exhausted": "1",
                                "dns_exit_resume": json.dumps({
                                    "resume_id": "resume-bounded",
                                    "incident_id": "dns-bounded", "scope": "all",
                                    "slot_id": "cloudflare-proxy",
                                    "active_kind": "node_wide_automatic",
                                    "profile_class": "all-present",
                                    "boot_id": "boot-test",
                                    "scope_identity": "scope-test",
                                    "attempt_seq": 3, "retry_monotonic": 0})})
        with mock.patch.object(dns_rescue, "_boot_id", return_value="boot-test"), \
             mock.patch.object(dns_rescue.dns_runtime, "emergency_route_state",
                               return_value="ready"), \
             mock.patch.object(dns_rescue, "_activate_locked") as activate:
            result = dns_rescue._resume_after_exit_failure_locked(
                self.cfg, self.pool)
        self.assertEqual(result["action"], "resume-exhausted")
        activate.assert_not_called()
        self.assertIsNone(self.pool.get_setting("dns_exit_resume"))
        self.assertEqual(self.pool.dns_state()["last_error"],
                         "exit-resume-exhausted")

    def test_stale_automatic_exit_resume_cannot_attach_to_new_incident(self):
        self.pool.set_settings({"automat_state": "EMERGENCY",
                                "dns_incident_id": "incident-new",
                                "dns_recovery_exhausted": "1",
                                "dns_exit_resume": json.dumps({
                                    "resume_id": "resume-stale",
                                    "incident_id": "incident-old", "scope": "all",
                                    "slot_id": "cloudflare-proxy",
                                    "active_kind": "node_wide_automatic",
                                    "profile_class": "all-present",
                                    "boot_id": "boot-test",
                                    "scope_identity": "scope-test",
                                    "attempt_seq": 0, "retry_monotonic": 0})})
        with mock.patch.object(dns_rescue, "_boot_id", return_value="boot-test"), \
             mock.patch.object(dns_rescue, "_activate_locked") as activate:
            result = dns_rescue._resume_after_exit_failure_locked(
                self.cfg, self.pool)
        self.assertEqual(result["action"], "resume-cancelled")
        self.assertIsNone(self.pool.get_setting("dns_exit_resume"))
        activate.assert_not_called()

    def test_stale_automatic_boot_resume_cannot_attach_to_new_incident(self):
        self.pool.set_settings({"automat_state": "EMERGENCY",
                                "dns_incident_id": "incident-new",
                                "dns_recovery_exhausted": "1",
                                "dns_boot_resume": json.dumps({
                                    "resume_id": "boot-stale",
                                    "incident_id": "incident-old", "scope": "all",
                                    "slot_id": "cloudflare-proxy",
                                    "active_kind": "node_wide_automatic",
                                    "profile_class": "all-present",
                                    "scope_identity": "scope-test",
                                    "attempt_seq": 0, "retry_monotonic": 0})})
        with mock.patch.object(dns_rescue, "_boot_id", return_value="boot-new"), \
             mock.patch.object(dns_rescue, "_physical", return_value=False), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "wireguard_scope_identity",
                               return_value="scope-test"), \
             mock.patch.object(dns_rescue, "_activate_locked") as activate:
            result = dns_rescue._resume_after_boot_locked(
                self.cfg, self.pool)
        self.assertEqual(result["action"], "boot-resume-cancelled")
        self.assertIsNone(self.pool.get_setting("dns_boot_resume"))
        activate.assert_not_called()

    def test_boot_resume_waits_boundedly_for_wireguard_identity(self):
        self.pool.set_settings({"automat_state": "EMERGENCY",
                                "dns_incident_id": "incident-boot",
                                "dns_recovery_exhausted": "1",
                                "dns_boot_resume": json.dumps({
                                    "resume_id": "boot-wg-wait",
                                    "incident_id": "incident-boot", "scope": "all",
                                    "slot_id": "cloudflare-proxy",
                                    "active_kind": "node_wide_automatic",
                                    "profile_class": "all-present",
                                    "scope_identity": "scope-test",
                                    "attempt_seq": 0, "retry_monotonic": 0})})
        with mock.patch.object(dns_rescue, "_boot_id", return_value="boot-new"), \
             mock.patch.object(dns_rescue, "_physical", return_value=False), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "wireguard_scope_identity_state",
                               return_value={"status": "unknown",
                                             "identity": None}), \
             mock.patch.object(dns_rescue, "_activate_locked") as activate:
            result = dns_rescue._resume_after_boot_locked(
                self.cfg, self.pool)
        self.assertEqual(result["action"], "boot-resume-retry-pending")
        activate.assert_not_called()
        resume = json.loads(self.pool.get_setting("dns_boot_resume"))
        self.assertEqual(resume["attempt_seq"], 1)
        self.assertFalse(resume["exhausted"])

    def test_active_but_unproven_resume_is_not_forgotten(self):
        self.pool.set_setting("dns_exit_resume", json.dumps({
            "resume_id": "resume-1", "incident_id": "manual-test",
            "scope": "all", "slot_id": "cloudflare-proxy",
            "active_kind": "node_wide_automatic",
            "profile_class": "all-present", "boot_id": "boot-test",
            "scope_identity": "scope-test"}))
        self.pool.set_dns_state(phase="recovering", active_scope="all",
                                active_slot="cloudflare-proxy",
                                active_kind="node_wide_automatic")
        with mock.patch.object(dns_rescue, "_physical", return_value=False):
            result = dns_rescue._resume_after_exit_failure_locked(
                self.cfg, self.pool)
        self.assertEqual(result["action"], "resume-active-unproven")
        self.assertIsNotNone(self.pool.get_setting("dns_exit_resume"))

    def test_pre_exit_unknown_proof_does_not_teardown_or_publish_resume(self):
        self._seed_nodewide_committed(boot_id="boot-test")
        with mock.patch.object(dns_rescue.os, "name", "posix"), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "firewall_attached", return_value=True), \
             mock.patch.object(dns_rescue, "_pre_exit_physical_state",
                               return_value="unknown"), \
             mock.patch.object(dns_rescue, "_deactivate_locked") as deactivate:
            result = dns_rescue.prepare_for_emergency_exit(
                self.cfg, self.pool, _locked=True)
        self.assertEqual(result["action"], "dns-exit-proof-unknown")
        self.assertIsNone(self.pool.get_setting("dns_exit_resume"))
        deactivate.assert_not_called()

    def test_isolated_hard_ttl_precedes_unknown_boot_inspection(self):
        self.pool.set_dns_state(
            phase="active_isolated", configured_mode="manual_canary",
            incident_id="manual-test", active_scope="peer:10.77.0.9",
            active_slot="cloudflare-proxy", active_kind="isolated_manual",
            expires_at="2000-01-01 00:00:00", expires_monotonic=0,
            scope_identity="scope-test", boot_id="boot-test")
        expected = {"ok": True, "action": "deactivated",
                    "state": self.pool.dns_state()}
        with mock.patch.object(dns_rescue, "_boot_id", return_value=None), \
             mock.patch.object(dns_rescue, "_deactivate_locked",
                               return_value=expected) as deactivate:
            result = dns_rescue.automatic_tick(
                self.cfg, self.pool, "OK", _locked=True)
        self.assertEqual(result["action"], "deactivated")
        self.assertEqual(deactivate.call_args.args[3], "isolated-ttl")

    def test_reconcile_never_keeps_physically_active_isolated_after_ttl(self):
        self.pool.set_dns_state(
            phase="active_isolated", configured_mode="manual_canary",
            incident_id="manual-test", active_scope="peer:10.77.0.9",
            active_slot="cloudflare-proxy", active_kind="isolated_manual",
            expires_at="2000-01-01 00:00:00", expires_monotonic=0,
            scope_identity="scope-test", boot_id="boot-test")
        with mock.patch.object(dns_rescue.dns_runtime,
                               "scrub_candidate_sidecar", return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "scrub_primary_test_bypass", return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "firewall_attached", return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "deactivate_redirect", return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "service_stop", return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "remove_listener_acl", return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "service_state") as service_state:
            state = dns_rescue._reconcile_locked(self.cfg, self.pool, "test")
        self.assertEqual(state["phase"], "idle")
        self.assertIsNone(state["active_scope"])
        service_state.assert_not_called()

    def test_expired_current_sidecar_reject_preserves_recent_untouched_runtime(self):
        self.cfg = normalized("automatic_last_resort", True, True)
        self.cfg["singbox_config"] = os.path.join(self.tmp.name, "main.json")
        self.cfg["dns_rescue"]["candidates"][0]["not_after"] = \
            "2000-01-01T00:00:00Z"
        self.pool.set_settings({"automat_state": "EMERGENCY",
                                "dns_incident_id": "dns-boot",
                                "dns_recovery_exhausted": "1"})
        state = self._seed_nodewide_committed(boot_id="boot-test")
        chosen = self.cfg["dns_rescue"]["candidates"][1]
        with mock.patch.object(dns_rescue, "_validate_scope_locked"), \
             mock.patch.object(dns_rescue, "_boot_id", return_value="boot-test"), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "wireguard_scope_identity",
                               return_value="scope-test"), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "candidate_sidecar_preflight_proven",
                               return_value=False), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "service_state", return_value="active"), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "firewall_effective", return_value=True), \
             mock.patch.object(dns_rescue, "probe_backend") as old_probe:
            result = dns_rescue._switch_active_candidate_locked(
                self.cfg, self.pool, state, chosen, "all-present",
                time.monotonic() + 30, print)
        self.assertEqual(
            result["action"], "successor-rejected-current-preserved")
        old_probe.assert_not_called()

    def test_expired_service_unknown_threshold_detaches_before_successor(self):
        self.cfg = normalized("automatic_last_resort", True, True)
        self.cfg["dns_rescue"]["candidates"][0]["not_after"] = \
            "2000-01-01T00:00:00Z"
        self.pool.set_settings({"automat_state": "EMERGENCY",
                                "emergency_manual": "0",
                                "dns_incident_id": "dns-boot",
                                "dns_recovery_exhausted": "1"})
        self._seed_nodewide_committed(boot_id="boot-test")
        self.pool.set_dns_state(
            active_failures=self.cfg["dns_rescue"]["active_failures"] - 1)
        expected = {"ok": True, "action": "backend-failover",
                    "state": self.pool.dns_state()}
        with mock.patch.object(dns_rescue, "_boot_id", return_value="boot-test"), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "emergency_route_state", return_value="ready"), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "wireguard_scope_identity_state",
                               return_value={"status": "valid",
                                             "identity": "scope-test"}), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "service_state", return_value="unknown"), \
             mock.patch.object(dns_rescue, "_failover_locked",
                               return_value=expected) as failover:
            result = dns_rescue.automatic_tick(
                self.cfg, self.pool, "EMERGENCY", _locked=True)
        self.assertEqual(result["action"], "backend-failover")
        self.assertFalse(failover.call_args.kwargs["current_runtime_proven"])

    def test_nodewide_route_drift_is_repaired_before_destructive_tick(self):
        self.cfg = normalized("automatic_last_resort", True, True)
        self.pool.set_settings({"automat_state": "EMERGENCY",
                                "emergency_manual": "0",
                                "dns_incident_id": "dns-boot",
                                "dns_recovery_exhausted": "1"})
        self._seed_nodewide_committed(boot_id="boot-test")
        self.pool.set_dns_state(active_last_check=dns_rescue._now())
        with mock.patch.object(dns_rescue, "_boot_id", return_value="boot-test"), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "emergency_route_state", return_value="mismatch"), \
             mock.patch.object(dns_rescue, "_ensure_resume_emergency_route",
                               return_value="ready") as repair, \
             mock.patch.object(dns_rescue.dns_runtime,
                               "wireguard_scope_identity_state",
                               return_value={"status": "valid",
                                             "identity": "scope-test"}), \
             mock.patch.object(dns_rescue, "_deactivate_locked") as deactivate:
            result = dns_rescue.automatic_tick(
                self.cfg, self.pool, "EMERGENCY", _locked=True)
        self.assertEqual(result["action"], "active")
        repair.assert_called_once()
        deactivate.assert_not_called()

    def test_unrepairable_route_drift_publishes_resume_before_teardown(self):
        self.cfg = normalized("automatic_last_resort", True, True)
        self.pool.set_settings({"automat_state": "EMERGENCY",
                                "emergency_manual": "0",
                                "dns_incident_id": "dns-boot",
                                "dns_recovery_exhausted": "1"})
        self._seed_nodewide_committed(boot_id="boot-test")

        def stop(*_args):
            descriptor = json.loads(self.pool.get_setting("dns_exit_resume"))
            self.assertEqual(descriptor["scope_identity"], "scope-test")
            return {"ok": True, "action": "deactivated",
                    "state": self.pool.dns_state()}

        with mock.patch.object(dns_rescue, "_boot_id", return_value="boot-test"), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "emergency_route_state", return_value="mismatch"), \
             mock.patch.object(dns_rescue, "_ensure_resume_emergency_route",
                               return_value="failed"), \
             mock.patch.object(dns_rescue, "_deactivate_locked",
                               side_effect=stop):
            result = dns_rescue.automatic_tick(
                self.cfg, self.pool, "EMERGENCY", _locked=True)
        self.assertTrue(result["resume_pending"])
        self.assertIsNotNone(self.pool.get_setting("dns_exit_resume"))

    def test_reconcile_inactive_owned_generation_detaches_then_resumes(self):
        self.cfg = normalized("automatic_last_resort", True, True)
        self.pool.set_settings({"automat_state": "EMERGENCY",
                                "emergency_manual": "0",
                                "dns_incident_id": "dns-boot",
                                "dns_recovery_exhausted": "1"})
        original = self._seed_nodewide_committed(boot_id="boot-test")
        original = self.pool.set_dns_state(attempt_used=True)
        order = []
        restored = dict(original, phase="active_proxy", active_scope="all",
                        active_slot="google-proxy",
                        active_kind="node_wide_automatic")

        def detach(*_args, **_kwargs):
            descriptor = json.loads(self.pool.get_setting("dns_exit_resume"))
            self.assertEqual(descriptor["incident_id"], "dns-boot")
            self.assertEqual(descriptor["scope_identity"], "scope-test")
            order.append("detach")
            return True

        def resume(*args, **kwargs):
            order.append("successor")
            return self._resume_success("dns_exit_resume", restored)(*args, **kwargs)

        with mock.patch.object(dns_rescue.os, "name", "posix"), \
             mock.patch.object(dns_rescue, "_boot_id", return_value="boot-test"), \
             mock.patch.object(dns_rescue.dns_runtime, "scrub_candidate_sidecar"), \
             mock.patch.object(dns_rescue.dns_runtime, "scrub_primary_test_bypass"), \
             mock.patch.object(dns_rescue.dns_runtime, "firewall_attached", return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "service_state", return_value="inactive"), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "wireguard_scope_identity_state",
                               return_value={"status": "valid", "identity": "scope-test"}), \
             mock.patch.object(dns_rescue.dns_runtime, "emergency_route_state",
                               return_value="ready"), \
             mock.patch.object(dns_rescue.dns_runtime, "firewall_effective", return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "deactivate_redirect",
                               side_effect=detach), \
             mock.patch.object(dns_rescue.dns_runtime, "service_stop"), \
             mock.patch.object(dns_rescue.dns_runtime, "remove_listener_acl"), \
             mock.patch.object(dns_rescue, "_activate_locked", side_effect=resume):
            state = dns_rescue.reconcile(self.cfg, self.pool, _locked=True)
        self.assertEqual(order, ["detach", "successor"])
        self.assertEqual(state["active_slot"], "google-proxy")
        self.assertEqual(state["incident_id"], "dns-boot")
        self.assertTrue(state["attempt_used"])
        self.assertIsNone(self.pool.get_setting("dns_exit_resume"))

    def test_reconcile_owned_route_drift_detaches_repairs_then_resumes(self):
        self.cfg = normalized("automatic_last_resort", True, True)
        self.pool.set_settings({"automat_state": "EMERGENCY",
                                "emergency_manual": "0",
                                "dns_incident_id": "dns-boot",
                                "dns_recovery_exhausted": "1"})
        original = self._seed_nodewide_committed(boot_id="boot-test")
        original = self.pool.set_dns_state(attempt_used=True)
        restored = dict(original, phase="active_proxy", active_scope="all",
                        active_slot="google-proxy",
                        active_kind="node_wide_automatic")
        order = []

        def detach(*_args, **_kwargs):
            self.assertIsNotNone(self.pool.get_setting("dns_exit_resume"))
            order.append("detach")
            return True

        def repair(*_args, **_kwargs):
            order.append("repair")
            return "ready"

        def resume(*args, **kwargs):
            order.append("successor")
            return self._resume_success("dns_exit_resume", restored)(*args, **kwargs)

        with mock.patch.object(dns_rescue.os, "name", "posix"), \
             mock.patch.object(dns_rescue, "_boot_id", return_value="boot-test"), \
             mock.patch.object(dns_rescue.dns_runtime, "scrub_candidate_sidecar"), \
             mock.patch.object(dns_rescue.dns_runtime, "scrub_primary_test_bypass"), \
             mock.patch.object(dns_rescue.dns_runtime, "firewall_attached", return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "service_state", return_value="active"), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "wireguard_scope_identity_state",
                               return_value={"status": "valid", "identity": "scope-test"}), \
             mock.patch.object(dns_rescue.dns_runtime, "emergency_route_state",
                               return_value="mismatch"), \
             mock.patch.object(dns_rescue.dns_runtime, "firewall_effective", return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "deactivate_redirect",
                               side_effect=detach), \
             mock.patch.object(dns_rescue.dns_runtime, "service_stop"), \
             mock.patch.object(dns_rescue.dns_runtime, "remove_listener_acl"), \
             mock.patch.object(dns_rescue, "_ensure_resume_emergency_route",
                               side_effect=repair), \
             mock.patch.object(dns_rescue, "_activate_locked", side_effect=resume):
            state = dns_rescue.reconcile(self.cfg, self.pool, _locked=True)
        self.assertEqual(order, ["detach", "repair", "successor"])
        self.assertEqual(state["active_slot"], "google-proxy")
        self.assertEqual(state["incident_id"], "dns-boot")
        self.assertTrue(state["attempt_used"])
        self.assertIsNone(self.pool.get_setting("dns_exit_resume"))

    def _assert_reconcile_partial_unknown_resumes(self, service_state, route_state):
        self.cfg = normalized("automatic_last_resort", True, True)
        self.pool.set_settings({"automat_state": "EMERGENCY",
                                "emergency_manual": "0",
                                "dns_incident_id": "dns-boot",
                                "dns_recovery_exhausted": "1"})
        original = self._seed_nodewide_committed(boot_id="boot-test")
        original = self.pool.set_dns_state(attempt_used=True)
        restored = dict(original, phase="active_proxy", active_scope="all",
                        active_slot="google-proxy",
                        active_kind="node_wide_automatic")

        def detach(*_args, **_kwargs):
            self.assertIsNotNone(self.pool.get_setting("dns_exit_resume"))
            return True

        with mock.patch.object(dns_rescue.os, "name", "posix"), \
             mock.patch.object(dns_rescue, "_boot_id", return_value="boot-test"), \
             mock.patch.object(dns_rescue.dns_runtime, "scrub_candidate_sidecar"), \
             mock.patch.object(dns_rescue.dns_runtime, "scrub_primary_test_bypass"), \
             mock.patch.object(dns_rescue.dns_runtime, "firewall_attached", return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "service_state",
                               return_value=service_state), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "wireguard_scope_identity_state",
                               return_value={"status": "valid", "identity": "scope-test"}), \
             mock.patch.object(dns_rescue.dns_runtime, "emergency_route_state",
                               return_value=route_state), \
             mock.patch.object(dns_rescue.dns_runtime, "firewall_effective", return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "deactivate_redirect",
                               side_effect=detach), \
             mock.patch.object(dns_rescue.dns_runtime, "service_stop"), \
             mock.patch.object(dns_rescue.dns_runtime, "remove_listener_acl"), \
             mock.patch.object(dns_rescue, "_ensure_resume_emergency_route",
                               return_value="ready"), \
             mock.patch.object(dns_rescue, "_activate_locked",
                               side_effect=self._resume_success(
                                   "dns_exit_resume", restored)):
            state = dns_rescue.reconcile(self.cfg, self.pool, _locked=True)
        self.assertEqual(state["active_slot"], "google-proxy")
        self.assertEqual(state["incident_id"], "dns-boot")
        self.assertTrue(state["attempt_used"])
        self.assertIsNone(self.pool.get_setting("dns_exit_resume"))

    def test_reconcile_inactive_listener_with_unknown_route_keeps_continuation(self):
        self._assert_reconcile_partial_unknown_resumes("inactive", "unknown")

    def test_reconcile_route_mismatch_with_unknown_listener_keeps_continuation(self):
        self._assert_reconcile_partial_unknown_resumes("unknown", "mismatch")

    def test_reconcile_inactive_listener_with_unknown_boot_keeps_continuation(self):
        self.cfg = normalized("automatic_last_resort", True, True)
        self.pool.set_settings({"automat_state": "EMERGENCY",
                                "emergency_manual": "0",
                                "dns_incident_id": "dns-boot",
                                "dns_recovery_exhausted": "1"})
        original = self._seed_nodewide_committed(boot_id="boot-test")
        original = self.pool.set_dns_state(attempt_used=True)
        events = []

        def detach(*_args, **_kwargs):
            descriptor = json.loads(self.pool.get_setting("dns_exit_resume"))
            self.assertEqual(descriptor["boot_id"], "boot-test")
            self.assertEqual(descriptor["scope_identity"], "scope-test")
            events.append("detach")
            return True

        with mock.patch.object(dns_rescue.os, "name", "posix"), \
             mock.patch.object(dns_rescue, "_boot_id", return_value=None), \
             mock.patch.object(dns_rescue.dns_runtime, "scrub_candidate_sidecar"), \
             mock.patch.object(dns_rescue.dns_runtime, "scrub_primary_test_bypass"), \
             mock.patch.object(dns_rescue.dns_runtime, "firewall_attached", return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "service_state",
                               return_value="inactive"), \
             mock.patch.object(dns_rescue.dns_runtime,
                               "wireguard_scope_identity_state",
                               return_value={"status": "valid", "identity": "scope-test"}), \
             mock.patch.object(dns_rescue.dns_runtime, "emergency_route_state",
                               return_value="ready"), \
             mock.patch.object(dns_rescue.dns_runtime, "firewall_effective", return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "deactivate_redirect",
                               side_effect=detach), \
             mock.patch.object(dns_rescue.dns_runtime, "service_stop",
                               side_effect=lambda *_args: events.append("stop")), \
             mock.patch.object(dns_rescue.dns_runtime, "remove_listener_acl"):
            first = dns_rescue.reconcile(self.cfg, self.pool, _locked=True)
        self.assertEqual(events, ["detach", "stop"])
        self.assertEqual(first["phase"], "failed")
        self.assertIsNone(first["active_scope"])
        descriptor = json.loads(self.pool.get_setting("dns_exit_resume"))
        self.assertEqual(descriptor["incident_id"], "dns-boot")
        self.assertEqual(descriptor["attempt_seq"], 1)
        descriptor["retry_monotonic"] = 0
        self.pool.set_setting("dns_exit_resume", json.dumps(descriptor))

        restored = dict(original, phase="active_proxy", active_scope="all",
                        active_slot="google-proxy",
                        active_kind="node_wide_automatic")
        with mock.patch.object(dns_rescue.os, "name", "posix"), \
             mock.patch.object(dns_rescue, "_boot_id", return_value="boot-test"), \
             mock.patch.object(dns_rescue.dns_runtime, "scrub_candidate_sidecar"), \
             mock.patch.object(dns_rescue.dns_runtime, "scrub_primary_test_bypass"), \
             mock.patch.object(dns_rescue.dns_runtime, "firewall_attached", return_value=False), \
             mock.patch.object(dns_rescue.dns_runtime, "service_inactive", return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "emergency_route_state",
                               return_value="ready"), \
             mock.patch.object(dns_rescue, "_activate_locked",
                               side_effect=self._resume_success(
                                   "dns_exit_resume", restored)):
            second = dns_rescue.reconcile(self.cfg, self.pool, _locked=True)
        self.assertEqual(second["active_slot"], "google-proxy")
        self.assertEqual(second["incident_id"], "dns-boot")
        self.assertTrue(second["attempt_used"])
        self.assertIsNone(self.pool.get_setting("dns_exit_resume"))

    def test_reconcile_continuation_survives_kill_after_publish(self):
        self.cfg = normalized("automatic_last_resort", True, True)
        self.pool.set_settings({"automat_state": "EMERGENCY",
                                "emergency_manual": "0",
                                "dns_incident_id": "dns-boot",
                                "dns_recovery_exhausted": "1"})
        original = self._seed_nodewide_committed(boot_id="boot-test")
        original = self.pool.set_dns_state(attempt_used=True)
        restored = dict(original, phase="active_proxy", active_scope="all",
                        active_slot="google-proxy",
                        active_kind="node_wide_automatic")

        def killed(*_args, **_kwargs):
            self.assertIsNotNone(self.pool.get_setting("dns_exit_resume"))
            raise KeyboardInterrupt()

        common = (
            mock.patch.object(dns_rescue.os, "name", "posix"),
            mock.patch.object(dns_rescue, "_boot_id", return_value="boot-test"),
            mock.patch.object(dns_rescue.dns_runtime, "scrub_candidate_sidecar"),
            mock.patch.object(dns_rescue.dns_runtime, "scrub_primary_test_bypass"),
            mock.patch.object(dns_rescue.dns_runtime, "service_state", return_value="inactive"),
            mock.patch.object(dns_rescue.dns_runtime, "wireguard_scope_identity_state",
                              return_value={"status": "valid", "identity": "scope-test"}),
            mock.patch.object(dns_rescue.dns_runtime, "emergency_route_state",
                              return_value="ready"),
            mock.patch.object(dns_rescue.dns_runtime, "firewall_effective", return_value=True),
        )
        with common[0], common[1], common[2], common[3], common[4], common[5], \
                common[6], common[7], \
                mock.patch.object(dns_rescue.dns_runtime, "firewall_attached",
                                  return_value=True), \
                mock.patch.object(dns_rescue.dns_runtime, "deactivate_redirect",
                                  side_effect=killed):
            with self.assertRaises(KeyboardInterrupt):
                dns_rescue.reconcile(self.cfg, self.pool, _locked=True)
        descriptor = json.loads(self.pool.get_setting("dns_exit_resume"))
        self.assertEqual(descriptor["incident_id"], "dns-boot")

        with mock.patch.object(dns_rescue.os, "name", "posix"), \
             mock.patch.object(dns_rescue, "_boot_id", return_value="boot-test"), \
             mock.patch.object(dns_rescue.dns_runtime, "scrub_candidate_sidecar"), \
             mock.patch.object(dns_rescue.dns_runtime, "scrub_primary_test_bypass"), \
             mock.patch.object(dns_rescue.dns_runtime, "firewall_attached", return_value=False), \
             mock.patch.object(dns_rescue.dns_runtime, "service_inactive", return_value=True), \
             mock.patch.object(dns_rescue.dns_runtime, "emergency_route_state",
                               return_value="ready"), \
             mock.patch.object(dns_rescue, "_activate_locked",
                               side_effect=self._resume_success(
                                   "dns_exit_resume", restored)):
            state = dns_rescue.reconcile(self.cfg, self.pool, _locked=True)
        self.assertEqual(state["active_slot"], "google-proxy")
        self.assertEqual(state["incident_id"], "dns-boot")
        self.assertIsNone(self.pool.get_setting("dns_exit_resume"))

    def test_nodewide_unknown_threshold_publishes_exact_resume_before_teardown(self):
        self.cfg = normalized("automatic_last_resort", True, True)
        state = self._seed_nodewide_committed(boot_id="boot-test")
        state = self.pool.set_dns_state(
            active_failures=self.cfg["dns_rescue"]["active_failures"] - 1)

        def stop(*_args):
            descriptor = json.loads(self.pool.get_setting("dns_exit_resume"))
            self.assertEqual(descriptor["scope_identity"], "scope-test")
            self.assertEqual(descriptor["boot_id"], "boot-test")
            return {"ok": True, "action": "deactivated",
                    "state": self.pool.dns_state()}

        with mock.patch.object(dns_rescue, "_deactivate_locked",
                               side_effect=stop):
            result = dns_rescue._hold_active_inspection_unknown(
                self.cfg, self.pool, state, "wireguard-scope")
        self.assertTrue(result["resume_pending"])
        self.assertIsNotNone(self.pool.get_setting("dns_exit_resume"))

    def test_corrupt_active_state_matrix_is_never_effective(self):
        corrupt = dict(
            self.pool.dns_state(), phase="active_isolated", active_scope="all",
            active_slot="cloudflare-proxy", active_kind="node_wide_manual",
            expires_at="2999-01-01 00:15:00", expires_monotonic=999999999.0)
        self.assertFalse(dns_rescue._state_shape_valid(self.cfg, corrupt))
        with mock.patch.object(dns_rescue.os, "name", "posix"):
            self.assertFalse(dns_rescue._physical(self.cfg, corrupt))

        corrupt = dict(self.pool.dns_state(), phase="idle",
                       active_scope="peer:10.77.0.9",
                       active_slot="cloudflare-proxy",
                       active_kind="isolated_manual")
        self.assertFalse(dns_rescue._state_shape_valid(self.cfg, corrupt))
        with mock.patch.object(dns_rescue.os, "name", "posix"):
            self.assertFalse(dns_rescue._physical(self.cfg, corrupt))


if __name__ == "__main__":
    unittest.main()
