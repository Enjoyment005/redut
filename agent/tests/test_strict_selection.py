"""Strict contour 2 preserves an explicit manual pin across failures and drift."""
import contextlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import _ctx  # noqa: F401
import dns_policy
import pool as pool_mod
import states


def verification(ok):
    return {"ok": ok, "egress_ip": "203.0.113.10" if ok else None,
            "exit_cc": "cn" if ok else None, "tg_code": "200" if ok else "000",
            "why": "" if ok else "unavailable", "why_kind": None}


class StrictSelectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pool = pool_mod.Pool(str(self.root / "state.db"), server="test")
        self.addCleanup(self.pool.close)
        self.config_path = self.root / "config.json"
        self.core_path = self.root / "singbox.json"
        self.config_path.write_text(json.dumps({"countries": {"strategy": "reputation"}}))
        self.core = {"_strict_fixture": True, "outbounds": [
            {"type": "socks", "tag": "socks-out", "server": "203.0.113.10",
             "server_port": 1080}]}
        self.write_core()
        self.cfg = {"_source": str(self.config_path), "singbox_config": str(self.core_path),
                    "countries": {"strategy": "reputation"}, "contour_id": "2",
                    "emergency_intent": str(self.root / "emergency-intent"),
                    "emergency_flag": str(self.root / "emergency-flag")}
        self.uid = self.pool.upsert_proxy({
            "provider": "proxy6", "ext_id": "test", "host": "203.0.113.10",
            "ip": "203.0.113.10", "country": "cn", "ip_version": 4,
            "kind": "dedicated", "date_end": None, "descr": "test",
            "port_socks5": 1080, "port_http": 8080, "user": "", "password": ""})
        self.alerter = mock.Mock()
        contract = mock.patch.object(dns_policy, "strict", create=True,
                                     side_effect=lambda sb: bool(sb.get("_strict_fixture")))
        self.strict = contract.start()
        self.addCleanup(contract.stop)

    def write_core(self):
        self.core_path.write_text(json.dumps(self.core))

    def pin(self):
        states.set_manual_selection(self.pool, self.uid, "203.0.113.10")
        return {key: self.pool.get_setting(key) for key in (
            "selection_mode", "manual_uid", "manual_host", "manual_since",
            "desired_selection_revision", "applied_selection_revision")}

    def assert_pin(self, before):
        self.assertEqual(before, {key: self.pool.get_setting(key) for key in before})
        self.assertEqual(self.cfg["countries"]["strategy"], "reputation")
        self.assertEqual(json.loads(self.config_path.read_text())["countries"]["strategy"],
                         "reputation")

    @contextlib.contextmanager
    def runtime(self, *, health=True, retune=None, verify=None):
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(states.contours, "ensure_ready"))
            net = stack.enter_context(mock.patch.object(states, "net_alive", return_value=(True, "test")))
            stack.enter_context(mock.patch.object(states.apply_mod, "verify_for",
                                                  side_effect=verify, return_value=verification(False)))
            stack.enter_context(mock.patch.object(states, "singbox_health", return_value={"ok": health}))
            rt = stack.enter_context(mock.patch.object(states, "try_retune", return_value=retune or {
                "ok": False, "proxy_fault_confirmed": True}))
            rotate = stack.enter_context(mock.patch.object(states, "try_rotating", return_value={
                "ok": True, "verify": verification(True), "detail": "rotated"}))
            replenish = stack.enter_context(mock.patch.object(states, "try_replenish"))
            emergency = stack.enter_context(mock.patch.object(states, "emergency_on"))
            apply = stack.enter_context(mock.patch.object(states.apply_mod, "apply_candidate"))
            stack.enter_context(mock.patch.object(states, "ensure_reserve"))
            stack.enter_context(mock.patch.object(states.time, "sleep"))
            yield {"net": net, "retune": rt, "rotate": rotate, "replenish": replenish,
                   "emergency": emergency, "apply": apply}

    def cycle(self):
        return states._rotate_locked(self.cfg, {}, self.pool, self.alerter, "watchdog",
                                     "auto", lambda *_: None, {}, states.OK)

    def assert_blocked(self, result, calls):
        self.assertFalse(result["ok"])
        self.assertEqual(result["action"], "strict-manual-blocked")
        self.assertEqual(result["state"], states.DEGRADED)
        for key in ("rotate", "replenish", "emergency", "apply"):
            calls[key].assert_not_called()

    def test_confirmed_and_repeated_failures_keep_the_manual_pin(self):
        for retune in ({"ok": False, "proxy_fault_confirmed": True},
                       {"ok": False}, {"ok": False, "calm_failed": True}):
            with self.subTest(retune=retune):
                before = self.pin()
                self.pool.set_setting("calm_fail_streak", str(states.CALM_MAX_STREAK - 1))
                original = self.core_path.read_bytes()
                with self.runtime(retune=retune) as calls:
                    result = self.cycle()
                self.assert_blocked(result, calls)
                calls["retune"].assert_called_once()
                self.assert_pin(before)
                self.assertEqual(self.core_path.read_bytes(), original)

    def test_drift_of_host_or_outbound_identity_does_not_select_auto(self):
        for same_host in (False, True):
            with self.subTest(same_host=same_host):
                self.core["outbounds"][0].update(server="203.0.113.10", server_port=1080)
                self.write_core()
                before = self.pin()
                self.pool.set_setting("manual_outbound_fingerprint",
                                      states.apply_mod.outbound_fingerprint(self.core["outbounds"]))
                self.core["outbounds"][0].update(
                    server="203.0.113.10" if same_host else "203.0.113.11", server_port=1081)
                self.write_core()
                original = self.core_path.read_bytes()
                with self.runtime() as calls:
                    result = self.cycle()
                self.assert_blocked(result, calls)
                calls["net"].assert_not_called()
                calls["retune"].assert_not_called()
                self.assert_pin(before)
                self.assertEqual(self.core_path.read_bytes(), original)

    def test_self_heal_of_the_pinned_server_remains_available(self):
        before = self.pin()
        with self.runtime(health=False, verify=[verification(False), verification(True)]) as calls, \
                mock.patch.object(states, "try_self_heal", return_value=True) as repair:
            result = self.cycle()
        self.assertTrue(result["ok"])
        self.assertEqual(result["action"], "self-heal")
        repair.assert_called_once()
        calls["retune"].assert_not_called()
        calls["rotate"].assert_not_called()
        self.assert_pin(before)

    def test_retune_of_the_pinned_server_remains_available(self):
        before = self.pin()
        with self.runtime(retune={"ok": True, "verify": verification(True)}) as calls:
            result = self.cycle()
        self.assertTrue(result["ok"])
        self.assertEqual(result["action"], "retune")
        calls["retune"].assert_called_once()
        calls["rotate"].assert_not_called()
        self.assert_pin(before)

    def test_explicit_auto_mode_can_rotate_in_strict_contour(self):
        self.pin()
        states.set_auto_selection(self.pool, self.cfg, strategy="reputation")
        with self.runtime() as calls:
            result = self.cycle()
        self.assertTrue(result["ok"])
        self.assertEqual(result["action"], "rotate")
        calls["rotate"].assert_called_once()
        self.assertEqual(self.pool.get_setting("selection_mode"), "auto")

    def test_primary_and_non_strict_contour_retain_existing_failover(self):
        for contour, strict in (("1", True), ("2", False)):
            with self.subTest(contour=contour, strict=strict):
                self.cfg["contour_id"] = contour
                self.core["_strict_fixture"] = strict
                self.write_core()
                self.pin()
                with self.runtime() as calls:
                    result = self.cycle()
                self.assertTrue(result["manual_released"])
                self.assertEqual(result["action"], "rotate")
                calls["rotate"].assert_called_once()
                self.assertEqual(self.pool.get_setting("selection_mode"), "auto")
                self.assertEqual(self.cfg["countries"]["strategy"], "speed")

    def test_primary_drift_retains_existing_release_to_auto(self):
        self.cfg["contour_id"] = "1"
        self.pin()
        self.core["outbounds"][0]["server"] = "203.0.113.11"
        self.write_core()
        with self.runtime(verify=[verification(True)]) as calls:
            result = self.cycle()
        self.assertTrue(result["ok"])
        self.assertEqual(result["action"], "noop")
        self.assertEqual(self.pool.get_setting("selection_mode"), "auto")
        self.assertEqual(self.cfg["countries"]["strategy"], "speed")
        calls["rotate"].assert_not_called()


if __name__ == "__main__":
    unittest.main()
