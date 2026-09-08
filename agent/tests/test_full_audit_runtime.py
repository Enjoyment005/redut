"""Offline regressions for full audit A03-A07; all external effects are mocked."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import _ctx
import agent
import apply
import dns_rescue
import dns_runtime
import health
import money
import pool
import states
from test_dns_rescue import normalized


class TestFullAuditRuntime(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="redut-audit-runtime-")
        self.addCleanup(self.tmp.cleanup)
        self.db = pool.Pool(os.path.join(self.tmp.name, "state.db"), server="test")
        self.addCleanup(self.db.close)
        uid = self.db.upsert_proxy(dict(
            provider="proxy6", ext_id="1", ip="203.0.113.2", host="203.0.113.2",
            port_http=8080, port_socks5=1080, user="SYNTHETIC_USER",
            password="SYNTHETIC_NEW_PASSWORD", country="fi", ip_version=4,
            kind="dedicated", date_end=None, descr=""))
        self.db.set_role(uid, "auto")
        self.db.conn.execute("UPDATE proxy SET probe_ok=1,fail_count=0,score=120 WHERE uid=?", (uid,))
        self.db.conn.commit()
        self.row = self.db.get(uid)
        self.cfg = {"singbox_config": os.path.join(self.tmp.name, "config.json"),
                    "ring": os.path.join(self.tmp.name, "ring"),
                    "lock": os.path.join(self.tmp.name, "lock"),
                    "boot_script": os.path.join(self.tmp.name, "absent.sh"),
                    "countries": {"strategy": "reputation"}}
        self.live = {"outbounds": [
            apply.build_outbound("socks", "socks-out", "203.0.113.1", 1080, "old", "old"),
            apply.build_outbound("http", "http-tg", "203.0.113.1", 8080, "old", "old")],
            "route": {"rules": []}}
        self.write_live(self.live)
        self.probe = dict(ok=True, disqualified=None, socks_port=1080, http_port=8080,
                          exit_ip="192.0.2.2", exit_cc="fi", tg_ok=True, tg_code="200",
                          latency_ms=50, score=100, matrix={})
        self.healthy = dict(ok=True, egress_ip="192.0.2.2", exit_cc="fi", tg_code="200")
        self.failed = dict(ok=False, egress_ip=None, exit_cc=None, tg_code=None,
                           why="synthetic verify failure", why_kind="no-ip")
        self.providers = {"proxy6": mock.Mock(caps={})}
        self.alerter = mock.Mock()
        self.log = lambda *_: None
        external_guards = contextlib.ExitStack()
        self.addCleanup(external_guards.close)
        external_guards.enter_context(mock.patch(
            "subprocess.run", side_effect=AssertionError("Real subprocess forbidden")))
        external_guards.enter_context(mock.patch(
            "socket.socket", side_effect=AssertionError("Real network forbidden")))

    def write_live(self, value):
        Path(self.cfg["singbox_config"]).write_text(json.dumps(value), encoding="utf-8")

    def system_ok(self):
        return mock.patch.multiple(apply,
            singbox_check=mock.Mock(return_value=(0, "")),
            antiloop_replace=mock.Mock(return_value=""),
            restart_singbox=mock.Mock(return_value=True),
            wait_tun0=mock.Mock(return_value=True),
            verify_egress=mock.Mock(return_value=self.healthy))

    @staticmethod
    def inconclusive_probe():
        return {"ok": False, "disqualified": "no-combo", "evidence": [
            health.evidence("http", False, target="https://api.ipify.org", via_proxy=True),
            health.evidence("http", True, target="https://www.gstatic.com/generate_204", via_proxy=True)]}

    def reconcile_firewall(self, strict_result=True, error=None, identity="synthetic-scope", route="ready"):
        cfg = normalized("automatic_last_resort", True, True)
        self.db.set_dns_state(phase="active_proxy", configured_mode="automatic_last_resort",
            incident_id="synthetic-incident", active_scope="all", active_slot="cloudflare-proxy",
            active_kind="node_wide_automatic", generation="synthetic-generation",
            scope_identity="synthetic-scope", boot_id="synthetic-boot", attempt_used=True)
        patches = {
            "scrub_candidate_sidecar": mock.Mock(), "scrub_primary_test_bypass": mock.Mock(),
            "firewall_attached": mock.Mock(return_value=True),
            "service_state": mock.Mock(return_value="active"),
            "wireguard_scope_identity_state": mock.Mock(return_value={"status": "valid", "identity": identity}),
            "emergency_route_state": mock.Mock(return_value=route),
            "_firewall_attached_strict": mock.Mock(return_value=strict_result, side_effect=error),
            "service_stop": mock.Mock(), "remove_listener_acl": mock.Mock()}
        with mock.patch.multiple(dns_runtime, **patches), \
             mock.patch.object(dns_rescue, "_boot_id", return_value="synthetic-boot"), \
             mock.patch.object(dns_rescue, "_detach_redirect_locked", return_value=True) as detach:
            result = dns_rescue._reconcile_locked(cfg, self.db, "test")
        return result, detach, patches

    def test_a03_firewall_inspection_error_preserves_active_generation(self):
        result, detach, patches = self.reconcile_firewall(error=dns_runtime.DNSRuntimeError("inspection timeout"))
        self.assertFalse(detach.called)
        self.assertFalse(patches["service_stop"].called)
        self.assertEqual(result["phase"], "active_proxy")
        self.assertEqual(result["active_scope"], "all")
        self.assertEqual(result["generation"], "synthetic-generation")
        self.assertEqual(result["last_error"], "ownership-inspection-unknown")

    def test_a03_confirmed_missing_firewall_still_cleans_up(self):
        result, detach, patches = self.reconcile_firewall(strict_result=False)
        self.assertTrue(detach.called)
        self.assertTrue(patches["service_stop"].called)
        self.assertIsNone(result["active_scope"])

    def test_a03_unknown_firewall_does_not_hide_confirmed_wrong_owner(self):
        result, detach, _ = self.reconcile_firewall(
            error=dns_runtime.DNSRuntimeError("inspection timeout"), identity="wrong-owner")
        self.assertTrue(detach.called)
        self.assertIsNone(result["active_scope"])

    def test_a03_auxiliary_timeouts_never_override_serving_generation_proof(self):
        cases = (
            ("first-read", [dns_runtime.DNSRuntimeError("timeout"), False, False], None, True),
            ("last-read", [False, False, dns_runtime.DNSRuntimeError("timeout")], None, True),
            ("sidecar", [False, False, False], dns_runtime.DNSRuntimeError("timeout"), True),
            ("main-unknown", [False, False, dns_runtime.DNSRuntimeError("timeout")], None, None),
        )
        for name, reads, sidecar_error, effective in cases:
            with self.subTest(case=name):
                self.reconcile_firewall()
                cfg = normalized("automatic_last_resort", True, True)
                with mock.patch.object(dns_runtime, "scrub_candidate_sidecar", side_effect=sidecar_error), \
                     mock.patch.object(dns_runtime, "_chain_present_strict", side_effect=reads), \
                     mock.patch.object(dns_runtime, "_references_to_chain", return_value=[]), \
                     mock.patch.object(dns_runtime, "firewall_attached", return_value=True), \
                     mock.patch.object(dns_runtime, "firewall_effective", return_value=effective), \
                     mock.patch.object(dns_runtime, "service_state", return_value="active"), \
                     mock.patch.object(dns_runtime, "wireguard_scope_identity_state", return_value={
                         "status": "valid", "identity": "synthetic-scope"}), \
                     mock.patch.object(dns_runtime, "emergency_route_state", return_value="ready"), \
                     mock.patch.object(dns_runtime, "service_stop") as stop, \
                     mock.patch.object(dns_runtime, "remove_listener_acl"), \
                     mock.patch.object(dns_rescue, "_boot_id", return_value="synthetic-boot"), \
                     mock.patch.object(dns_rescue, "_detach_redirect_locked", return_value=True) as detach:
                    result = dns_rescue._reconcile_locked(cfg, self.db, "test")
                detach.assert_not_called()
                stop.assert_not_called()
                self.assertEqual(result["phase"], "active_proxy")
                self.assertEqual(result["generation"], "synthetic-generation")

    def test_a03_auxiliary_error_does_not_hide_confirmed_main_firewall_mismatch(self):
        self.reconcile_firewall()
        cfg = normalized("automatic_last_resort", True, True)
        with mock.patch.object(dns_runtime, "scrub_candidate_sidecar", side_effect=dns_runtime.DNSRuntimeError("timeout")), \
             mock.patch.object(dns_runtime, "scrub_primary_test_bypass"), \
             mock.patch.object(dns_runtime, "firewall_attached", return_value=True), \
             mock.patch.object(dns_runtime, "firewall_effective", return_value=False), \
             mock.patch.object(dns_runtime, "service_state", return_value="active"), \
             mock.patch.object(dns_runtime, "wireguard_scope_identity_state", return_value={
                 "status": "valid", "identity": "synthetic-scope"}), \
             mock.patch.object(dns_runtime, "emergency_route_state", return_value="ready"), \
             mock.patch.object(dns_runtime, "service_stop") as stop, \
             mock.patch.object(dns_runtime, "remove_listener_acl"), \
             mock.patch.object(dns_rescue, "_boot_id", return_value="synthetic-boot"), \
             mock.patch.object(dns_rescue, "_detach_redirect_locked", return_value=True) as detach:
            result = dns_rescue._reconcile_locked(cfg, self.db, "test")
        detach.assert_called_once()
        stop.assert_called_once()
        self.assertIsNone(result["active_scope"])

    def seed_six_candidates(self):
        for index in range(2, 7):
            address = "203.0.113.%d" % (index + 1)
            uid = self.db.upsert_proxy(dict(self.row, ext_id=str(index), ip=address, host=address))
            self.db.set_role(uid, "auto")
        return states.selectable_candidates(self.db, self.cfg, "203.0.113.1", self.providers)

    def test_a04_unknown_candidates_cannot_starve_sixth_candidate(self):
        candidates = self.seed_six_candidates()
        healthy = candidates[-1]
        calls = []
        def probe(row, **_kwargs):
            calls.append(row["uid"])
            return copy.deepcopy(self.probe if row["uid"] == healthy["uid"] else self.inconclusive_probe())
        applied = {"ok": True, "new_ip": healthy["host"], "verify": self.healthy}
        with mock.patch.object(states.probe_mod, "probe", side_effect=probe), \
             mock.patch.object(states.probe_mod, "score", return_value=None), \
             mock.patch.object(apply, "apply_candidate", return_value=applied) as mutation:
            first = states.try_rotating(self.cfg, self.providers, self.db, self.alerter, self.log, "auto")
            count_first = len(calls)
            self.db.upsert_proxy(dict(healthy, password="SYNTHETIC_REFRESHED"))
            second = states.try_rotating(self.cfg, self.providers, self.db, self.alerter, self.log, "auto")
        self.assertTrue(first["capped"])
        self.assertTrue(first.get("inconclusive"))
        self.assertLessEqual(count_first, states.MAX_CANDIDATES_PER_CYCLE)
        self.assertLessEqual(len(calls) - count_first, states.MAX_CANDIDATES_PER_CYCLE)
        self.assertTrue(second["ok"])
        self.assertEqual(set(calls), {row["uid"] for row in candidates})
        self.assertEqual(mutation.call_args.args[1]["password"], "SYNTHETIC_REFRESHED")
        self.assertTrue(all(not self.db.get(row["uid"])["cooldown_until"] for row in candidates))

    def test_a04_removed_cursor_uid_restarts_from_current_pool_with_bounded_budget(self):
        candidates = self.seed_six_candidates()
        with mock.patch.object(states.probe_mod, "probe", side_effect=lambda *_a, **_k: self.inconclusive_probe()), \
             mock.patch.object(states.probe_mod, "score", return_value=None):
            states.try_rotating(self.cfg, self.providers, self.db, self.alerter, self.log, "auto")
        self.db.conn.execute("DELETE FROM proxy WHERE uid=?", (candidates[-1]["uid"],))
        self.db.conn.commit()
        calls = []
        def probe(row, **_kwargs):
            calls.append(row["uid"])
            return self.inconclusive_probe()
        with mock.patch.object(states.probe_mod, "probe", side_effect=probe), \
             mock.patch.object(states.probe_mod, "score", return_value=None):
            result = states.try_rotating(self.cfg, self.providers, self.db, self.alerter, self.log, "auto")
        self.assertTrue(result["inconclusive"])
        self.assertFalse(result["exhausted"])
        self.assertEqual(set(calls), {row["uid"] for row in candidates[:-1]})
        self.assertLessEqual(len(calls), states.MAX_CANDIDATES_PER_CYCLE)

    def test_a04_capped_unknown_cycle_preserves_emergency(self):
        self.seed_six_candidates()
        self.test_a04_unknown_rotation_does_not_buy_or_clear_emergency()

    def test_a04_later_capped_cycle_preserves_emergency_with_prior_unknowns(self):
        for index in range(2, 12):
            address = "203.0.113.%d" % (index + 1)
            uid = self.db.upsert_proxy(dict(self.row, ext_id=str(index), ip=address, host=address))
            self.db.set_role(uid, "auto")
        candidates = states.selectable_candidates(self.db, self.cfg, "203.0.113.1", self.providers)
        unknown = {row["uid"] for row in candidates[:5]}
        self.db.set_setting("automat_state", "EMERGENCY")

        def probe(row, **_kwargs):
            if row["uid"] in unknown:
                return self.inconclusive_probe()
            return {"ok": False, "disqualified": "blocked-cc:ru"}

        with mock.patch.object(states, "reconcile_strategy_override"), \
             mock.patch.object(states, "net_alive", return_value=(True, "direct", [])), \
             mock.patch.object(apply, "verify_egress", return_value=self.failed), \
             mock.patch.object(states, "singbox_health", return_value={"ok": True}), \
             mock.patch.object(states, "try_retune", return_value={"ok": False, "proxy_fault_confirmed": True}), \
             mock.patch.object(states.probe_mod, "probe", side_effect=probe), \
             mock.patch.object(states.probe_mod, "score", return_value=None), \
             mock.patch.object(states, "emergency_on", return_value=True), \
             mock.patch.object(states, "_leave_direct") as leave, \
             mock.patch.object(states, "try_replenish") as replenish:
            results = [states._rotate_locked(self.cfg, self.providers, self.db, self.alerter,
                "watchdog", "auto", self.log, {}, self.db.get_setting("automat_state")) for _ in range(2)]
        self.assertEqual([result["state"] for result in results], ["EMERGENCY", "EMERGENCY"])
        eligible = states.selectable_candidates(self.db, self.cfg, "203.0.113.1", self.providers)
        self.assertTrue(unknown.issubset({row["uid"] for row in eligible}))
        replenish.assert_not_called()
        leave.assert_not_called()

    def test_a04_unknown_reserve_has_no_cooldown_or_exhaustion_and_blocks_purchase(self):
        pres = self.inconclusive_probe()
        with mock.patch.object(states.probe_mod, "probe", return_value=pres), \
             mock.patch.object(states.probe_mod, "score", return_value=None):
            rotation = states.try_rotating(self.cfg, self.providers, self.db, self.alerter, self.log, "auto")
        stored = self.db.get(self.row["uid"])
        with mock.patch("auto_purchase.purchase", side_effect=money.SpendDenied("synthetic gate")) as buy:
            replenish = states.try_replenish(self.cfg, self.providers, self.db, self.alerter, self.log, "auto")
        self.assertEqual(pres["persistence_outcome"], health.PROBE_INCONCLUSIVE)
        self.assertEqual(stored["probe_ok"], 1)
        self.assertFalse(stored["cooldown_until"])
        self.assertFalse(rotation["exhausted"])
        self.assertTrue(rotation["inconclusive"])
        buy.assert_not_called()
        self.assertTrue(replenish["have_candidates"])

    def test_a04_definitive_failure_exhausts_pool_and_sets_cooldown(self):
        pres = {"ok": False, "disqualified": "blocked-cc:ru"}
        with mock.patch.object(states.probe_mod, "probe", return_value=pres), \
             mock.patch.object(states.probe_mod, "score", return_value=None):
            result = states.try_rotating(self.cfg, self.providers, self.db, self.alerter, self.log, "auto")
        self.assertTrue(result["exhausted"])
        self.assertTrue(self.db.get(self.row["uid"])["cooldown_until"])

    def test_a04_unknown_rotation_does_not_buy_or_clear_emergency(self):
        self.db.set_setting("automat_state", "EMERGENCY")
        with mock.patch.object(states, "reconcile_strategy_override"), \
             mock.patch.object(states, "net_alive", return_value=(True, "direct", [])), \
             mock.patch.object(apply, "verify_egress", return_value=self.failed), \
             mock.patch.object(states, "singbox_health", return_value={"ok": True}), \
             mock.patch.object(states, "try_retune", return_value={"ok": False, "proxy_fault_confirmed": True}), \
             mock.patch.object(states.probe_mod, "probe", return_value=self.inconclusive_probe()), \
             mock.patch.object(states.probe_mod, "score", return_value=None), \
             mock.patch.object(states, "emergency_on", return_value=True), \
             mock.patch.object(states, "_leave_direct") as leave, \
             mock.patch.object(states, "try_replenish") as replenish:
            result = states._rotate_locked(self.cfg, self.providers, self.db, self.alerter,
                "watchdog", "auto", self.log, {}, "EMERGENCY")
        replenish.assert_not_called()
        leave.assert_not_called()
        self.assertEqual(result["state"], "EMERGENCY")
        self.assertIsNone(self.db.get_setting("emergency_last_retry"))

    def test_a04_strategy_unknown_preserves_health_and_cooldown(self):
        with mock.patch.object(states.probe_mod, "probe", return_value=self.inconclusive_probe()), \
             mock.patch.object(states.probe_mod, "score", return_value=None), \
             mock.patch.object(states, "reconcile_strategy_override"), \
             mock.patch.object(states.config_store, "refresh_country_strategy"), \
             mock.patch.object(apply, "apply_candidate") as mutation:
            result = states._converge_strategy_locked(self.cfg, self.providers, self.db, self.log)
        mutation.assert_not_called()
        self.assertEqual(result["action"], "probe-inconclusive")
        self.assertFalse(self.db.get(self.row["uid"])["cooldown_until"])

    def test_a04_provider_switch_unknown_does_not_cooldown(self):
        current = dict(self.row, uid="proxywing:old", provider="proxywing", host="203.0.113.1")
        with mock.patch.object(states.probe_mod, "probe", return_value=self.inconclusive_probe()), \
             mock.patch.object(states.probe_mod, "score", return_value=None), \
             mock.patch.object(apply, "apply_candidate") as mutation:
            states._switch_locked(self.cfg, self.providers, self.db, self.alerter,
                "proxywing", current["host"], current, self.log, "test", "key-removed", {})
        mutation.assert_not_called()
        self.assertFalse(self.db.get(self.row["uid"])["cooldown_until"])

    def test_a05_changed_credentials_create_new_operation_without_logging_secrets(self):
        old = dict(self.row, password="SYNTHETIC_OLD_PASSWORD")
        with self.system_ok(), mock.patch.object(apply, "restart_singbox", return_value=True) as restart:
            first = apply.apply_candidate(self.cfg, old, self.probe, pool=self.db, log=self.log)
            apply.commit_operation(self.db, first)
            second = apply.apply_candidate(self.cfg, self.row, self.probe, pool=self.db, log=self.log)
            apply.commit_operation(self.db, second)
            third = apply.apply_candidate(self.cfg, self.row, self.probe, pool=self.db, log=self.log)
        self.assertNotEqual(first["operation_id"], second["operation_id"])
        self.assertEqual(second["operation_id"], third["operation_id"])
        self.assertEqual(restart.call_count, 2)
        self.assertEqual(apply.load_json(self.cfg["singbox_config"])["outbounds"][0]["password"], self.row["password"])
        desired = json.dumps(self.db.get_operation(operation_id=second["operation_id"])["desired_state"])
        self.assertNotIn(self.row["password"], desired)
        self.assertNotIn(self.row["user"], desired)

    def test_a05_committed_apply_retry_requires_fresh_positive_verification(self):
        with self.system_ok(), mock.patch.object(apply, "verify_egress", return_value=self.healthy) as verify:
            first = apply.apply_candidate(self.cfg, self.row, self.probe, pool=self.db, log=self.log)
            apply.commit_operation(self.db, first)
            self.db.set_setting("automat_state", "EMERGENCY")
            verify.return_value = self.failed
            with self.assertRaises(apply.ApplyError):
                apply.apply_candidate(self.cfg, self.row, self.probe, pool=self.db, log=self.log)
        self.assertEqual(self.db.get_setting("automat_state"), "EMERGENCY")
        self.assertEqual(self.db.get_operation(operation_id=first["operation_id"])["phase"], "committed")

    def test_a05_explicit_key_cannot_replay_different_credentials(self):
        with self.system_ok(), mock.patch.object(apply, "restart_singbox", return_value=True) as restart:
            first = apply.apply_candidate(self.cfg, self.row, self.probe, pool=self.db,
                idempotency_key="synthetic-key", log=self.log)
            apply.commit_operation(self.db, first)
            with self.assertRaises(apply.ApplyError):
                apply.apply_candidate(self.cfg, dict(self.row, password="DIFFERENT_SYNTHETIC"),
                    self.probe, pool=self.db, idempotency_key="synthetic-key", log=self.log)
        self.assertEqual(restart.call_count, 1)

    def test_a05_explicit_terminal_retry_rejects_changed_live_config(self):
        with self.system_ok(), mock.patch.object(apply, "restart_singbox", return_value=True) as restart:
            first = apply.apply_candidate(self.cfg, self.row, self.probe, pool=self.db,
                idempotency_key="synthetic-key", log=self.log)
            apply.commit_operation(self.db, first)
            self.write_live(self.live)
            with self.assertRaises(apply.ApplyError):
                apply.apply_candidate(self.cfg, self.row, self.probe, pool=self.db,
                    idempotency_key="synthetic-key", log=self.log)
        self.assertEqual(restart.call_count, 1)

    def test_a05_committed_rollback_retry_requires_fresh_positive_verification(self):
        backup = os.path.join(self.tmp.name, "explicit-backup.json")
        Path(backup).write_text(json.dumps(self.live), encoding="utf-8")
        with self.system_ok(), mock.patch.object(apply, "verify_egress", return_value=self.healthy) as verify:
            apply.apply_candidate(self.cfg, self.row, self.probe, log=self.log)
            first = apply.rollback_from_ring(self.cfg, backup, pool=self.db, log=self.log)
            apply.commit_operation(self.db, first)
            verify.return_value = self.failed
            with self.assertRaises(apply.ApplyError):
                apply.rollback_from_ring(self.cfg, backup, pool=self.db, log=self.log)

    def test_a05_rollback_same_path_updated_content_creates_new_intent(self):
        backup = os.path.join(self.tmp.name, "explicit-backup.json")
        Path(backup).write_text(json.dumps(self.live), encoding="utf-8")
        with self.system_ok(), mock.patch.object(apply, "restart_singbox", return_value=True) as restart:
            apply.apply_candidate(self.cfg, self.row, self.probe, log=self.log)
            first = apply.rollback_from_ring(self.cfg, backup, pool=self.db, log=self.log)
            apply.commit_operation(self.db, first)
            revised = copy.deepcopy(self.live)
            revised["outbounds"][1]["password"] = "SYNTHETIC_REVISED_BACKUP"
            Path(backup).write_text(json.dumps(revised), encoding="utf-8")
            second = apply.rollback_from_ring(self.cfg, backup, pool=self.db, log=self.log)
            apply.commit_operation(self.db, second)
            third = apply.rollback_from_ring(self.cfg, backup, pool=self.db, log=self.log)
        self.assertNotEqual(first["operation_id"], second["operation_id"])
        self.assertEqual(second["operation_id"], third["operation_id"])
        self.assertEqual(restart.call_count, 3)
        self.assertEqual(apply.file_checksum(self.cfg["singbox_config"]), apply.file_checksum(backup))

    def test_a05_legacy_explicit_rollback_rejects_different_backup_content(self):
        backup = os.path.join(self.tmp.name, "explicit-backup.json")
        Path(backup).write_text(json.dumps(self.live), encoding="utf-8")
        with self.system_ok(), mock.patch.object(apply, "restart_singbox", return_value=True) as restart:
            apply.apply_candidate(self.cfg, self.row, self.probe, log=self.log)
            first = apply.rollback_from_ring(self.cfg, backup, pool=self.db,
                idempotency_key="rollback-legacy", log=self.log)
            apply.commit_operation(self.db, first)
            op = self.db.get_operation(operation_id=first["operation_id"])
            legacy = dict(op["desired_state"])
            legacy.pop("backup_checksum", None)
            self.db.conn.execute("UPDATE operation SET desired_state=? WHERE id=?",
                                (json.dumps(legacy), first["operation_id"]))
            self.db.conn.commit()
            same = apply.rollback_from_ring(self.cfg, backup, pool=self.db,
                idempotency_key="rollback-legacy", log=self.log)
            self.assertEqual(same["operation_id"], first["operation_id"])
            revised = copy.deepcopy(self.live)
            revised["outbounds"][1]["password"] = "SYNTHETIC_REVISED_BACKUP"
            Path(backup).write_text(json.dumps(revised), encoding="utf-8")
            with self.assertRaises(apply.ApplyError):
                apply.rollback_from_ring(self.cfg, backup, pool=self.db,
                    idempotency_key="rollback-legacy", log=self.log)
        self.assertEqual(restart.call_count, 2)

    def test_a06_retune_applies_changed_username_and_password(self):
        for field in ("username", "password"):
            with self.subTest(field=field):
                outs = apply.choose_outbounds(self.row["host"], self.row["user"], self.row["password"], 1080, 8080)
                live = apply.patch_config(self.live, *outs)
                live["outbounds"][1][field] = "SYNTHETIC_STALE"
                self.write_live(live)
                with self.system_ok(), mock.patch.object(states, "_probe", return_value=self.probe), \
                     mock.patch.object(apply, "restart_singbox", return_value=True) as restart:
                    result = states.try_retune(self.cfg, self.providers, self.db, self.alerter, self.log, "auto")
                self.assertTrue(result["ok"])
                self.assertFalse(result.get("calm"))
                self.assertEqual(restart.call_count, 1)
                persisted = apply.load_json(self.cfg["singbox_config"])["outbounds"][1]
                self.assertEqual(persisted[field], self.row["user" if field == "username" else "password"])

    def test_a06_unchanged_outbounds_keep_calm_restart(self):
        outs = apply.choose_outbounds(self.row["host"], self.row["user"], self.row["password"], 1080, 8080)
        self.write_live(apply.patch_config(self.live, *outs))
        with self.system_ok(), mock.patch.object(states, "_probe", return_value=self.probe), \
             mock.patch.object(apply, "apply_candidate") as mutation:
            result = states.try_retune(self.cfg, self.providers, self.db, self.alerter, self.log, "auto")
        self.assertTrue(result["calm"])
        mutation.assert_not_called()

    def test_a07_dry_run_hides_credentials_and_leaves_live_unchanged(self):
        before = Path(self.cfg["singbox_config"]).read_bytes()
        output = io.StringIO()
        with contextlib.redirect_stdout(output), \
             mock.patch.object(agent, "open_pool", return_value=mock.Mock(get=lambda _uid: self.row)), \
             mock.patch.object(agent, "load_secrets", return_value=({}, None)), \
             mock.patch.object(agent, "make_providers", return_value={}), \
             mock.patch.object(agent, "read_singbox", return_value=self.live), \
             mock.patch.object(agent, "_probe_one", return_value=self.probe), \
             mock.patch("shutil.which", return_value=None):
            rc = agent.cmd_apply(self.cfg, SimpleNamespace(uid=self.row["uid"], dry_run=True))
        self.assertEqual(rc, 0)
        self.assertNotIn(self.row["password"], output.getvalue())
        self.assertNotIn(self.row["user"], output.getvalue())
        self.assertEqual(Path(self.cfg["singbox_config"]).read_bytes(), before)
        self.assertFalse(list(Path(self.tmp.name).glob("config.json.stage*")))

    def test_a07_dry_run_failed_check_hides_credentials(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), \
             mock.patch.object(agent, "open_pool", return_value=mock.Mock(get=lambda _uid: self.row)), \
             mock.patch.object(agent, "load_secrets", return_value=({}, None)), \
             mock.patch.object(agent, "make_providers", return_value={}), \
             mock.patch.object(agent, "read_singbox", return_value=self.live), \
             mock.patch.object(agent, "_probe_one", return_value=self.probe), \
             mock.patch("shutil.which", return_value="synthetic-sing-box"), \
             mock.patch.object(apply, "singbox_check", return_value=(
                 1, "invalid: " + self.row["user"] + " " + self.row["password"])):
            rc = agent.cmd_apply(self.cfg, SimpleNamespace(uid=self.row["uid"], dry_run=True))
        self.assertEqual(rc, 1)
        self.assertNotIn(self.row["password"], output.getvalue())
        self.assertNotIn(self.row["user"], output.getvalue())
        self.assertFalse(list(Path(self.tmp.name).glob("config.json.stage*")))


if __name__ == "__main__":
    unittest.main()
