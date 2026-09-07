# -*- coding: utf-8 -*-
"""Regression contract between the main state machine and DNS Rescue."""
import os
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock


HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import agent
import dns_rescue
import pool as pool_mod
import states


class _NullAlerter:
    def emergency(self, **_kwargs):
        return None

    def recovered(self, **_kwargs):
        return None


class StateContractCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = {
            "db": os.path.join(self.tmp.name, "state.db"),
            "lock": os.path.join(self.tmp.name, "agent.lock"),
            "singbox_config": os.path.join(self.tmp.name, "config.json"),
        }
        self.pool = pool_mod.Pool(self.cfg["db"], server="test")
        self.alerter = _NullAlerter()

    def tearDown(self):
        self.pool.close()
        self.tmp.cleanup()

    def _rotate_patches(self):
        failed = {"ok": False, "why_kind": "", "egress_ip": None,
                  "evidence": []}
        return (
            mock.patch.object(states, "reconcile_strategy_override"),
            mock.patch.object(states.apply_mod, "load_json", return_value={}),
            mock.patch.object(states.apply_mod, "current_upstream", return_value="192.0.2.8"),
            mock.patch.object(states, "selection_state",
                              return_value={"mode": states.SELECTION_AUTO}),
            mock.patch.object(states, "net_alive",
                              return_value=(True, "direct", [])),
            mock.patch.object(states.apply_mod, "verify_egress", return_value=failed),
            mock.patch.object(states, "singbox_health",
                              return_value={"ok": True, "active": True, "tun0": True}),
            mock.patch.object(states, "try_retune",
                              return_value={"ok": False, "proxy_fault_confirmed": True}),
            mock.patch.object(states, "release_manual_on_fault",
                              return_value={"released": False}),
        )

    def _run_locked(self):
        result = {"state": None, "action": None, "detail": "", "ok": False}
        return states._rotate_locked(
            self.cfg, {}, self.pool, self.alerter, "watchdog", "auto",
            lambda *_: None, result, states.OK)

    def test_rate_limit_is_not_dns_recovery_exhaustion(self):
        self.pool.rotations_last_hour = mock.Mock(
            return_value=states.MAX_REPLACEMENTS_PER_HOUR)
        patches = self._rotate_patches()
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patches[5], patches[6], patches[7], patches[8], \
                mock.patch.object(states, "_enter_emergency", return_value=True) as enter:
            result = self._run_locked()
        self.assertEqual(result["action"], "rate-limited")
        self.assertFalse(enter.call_args.kwargs["recovery_exhausted"])

    def test_only_terminal_rotation_and_replenish_failure_is_eligible(self):
        self.pool.rotations_last_hour = mock.Mock(return_value=0)
        patches = self._rotate_patches()
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patches[5], patches[6], patches[7], patches[8], \
                mock.patch.object(states, "try_rotating",
                                  return_value={"ok": False, "exhausted": True}), \
                mock.patch.object(states, "try_replenish",
                                  return_value={"ok": False, "reason": "unavailable"}), \
                mock.patch.object(states, "_enter_emergency", return_value=True) as enter:
            result = self._run_locked()
        self.assertEqual(result["action"], "emergency")
        self.assertTrue(enter.call_args.kwargs["recovery_exhausted"])

    def test_capped_rotation_does_not_enter_dns_eligible_emergency(self):
        self.pool.rotations_last_hour = mock.Mock(return_value=0)
        patches = self._rotate_patches()
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patches[5], patches[6], patches[7], patches[8], \
                mock.patch.object(states, "try_rotating",
                                  return_value={"ok": False, "exhausted": False,
                                                "capped": True, "tried": 5,
                                                "total": 7}), \
                mock.patch.object(states, "emergency_on", return_value=True), \
                mock.patch.object(states, "_enter_emergency") as enter:
            result = self._run_locked()
        self.assertEqual(result["action"], "pool-probing")
        enter.assert_not_called()
        self.assertIsNone(self.pool.get_setting("dns_recovery_exhausted"))

    def test_nonterminal_replenish_result_is_not_eligible(self):
        self.pool.rotations_last_hour = mock.Mock(return_value=0)
        patches = self._rotate_patches()
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patches[5], patches[6], patches[7], patches[8], \
                mock.patch.object(states, "try_rotating",
                                  return_value={"ok": False, "exhausted": True}), \
                mock.patch.object(states, "try_replenish",
                                  return_value={"ok": False, "have_candidates": 2,
                                                "reason": "retry candidates first"}), \
                mock.patch.object(states, "_enter_emergency", return_value=True) as enter:
            self._run_locked()
        self.assertFalse(enter.call_args.kwargs["recovery_exhausted"])

    def test_existing_emergency_can_become_eligible_without_new_entry(self):
        self.pool.set_setting("automat_state", states.EMERGENCY)
        with mock.patch.object(states, "emergency_on", return_value=True), \
                mock.patch.object(dns_rescue, "automatic_tick",
                                  return_value={"ok": False, "action": "ineligible"}) as tick:
            ok = states._enter_emergency(
                self.cfg, self.pool, self.alerter, "terminal exhaustion",
                lambda *_: None, "auto", states.EMERGENCY,
                recovery_exhausted=True)
        self.assertTrue(ok)
        self.assertEqual(self.pool.get_setting("dns_recovery_exhausted"), "1")
        self.assertTrue(self.pool.get_setting("dns_incident_id").startswith("dns-"))
        tick.assert_called_once()

    def test_new_noneligible_emergency_discards_stale_incident_marker(self):
        self.pool.set_settings({"dns_incident_id": "dns-old",
                                "dns_recovery_exhausted": "1"})
        with mock.patch.object(states, "emergency_on", return_value=True), \
                mock.patch.object(dns_rescue, "automatic_tick") as tick:
            ok = states._enter_emergency(
                self.cfg, self.pool, self.alerter, "rate limited",
                lambda *_: None, "auto", states.OK,
                recovery_exhausted=False)
        self.assertTrue(ok)
        self.assertIsNone(self.pool.get_setting("dns_incident_id"))
        self.assertIsNone(self.pool.get_setting("dns_recovery_exhausted"))
        tick.assert_not_called()

    def test_exhausted_entry_publishes_incident_before_post_commit_crash(self):
        with mock.patch.object(states, "emergency_on", return_value=True), \
             mock.patch.object(self.pool, "log_event",
                               side_effect=RuntimeError("crash-after-commit")):
            with self.assertRaises(RuntimeError):
                states._enter_emergency(
                    self.cfg, self.pool, self.alerter, "terminal exhaustion",
                    lambda *_: None, "auto", states.OK,
                    recovery_exhausted=True)
        self.assertEqual(self.pool.get_setting("automat_state"), states.EMERGENCY)
        self.assertEqual(self.pool.get_setting("dns_recovery_exhausted"), "1")
        self.assertTrue(self.pool.get_setting("dns_incident_id").startswith("dns-"))

    def test_manual_entry_publishes_sticky_reference_before_post_commit_crash(self):
        with mock.patch.object(states, "emergency_on", return_value=True), \
             mock.patch.object(self.pool, "log_event",
                               side_effect=RuntimeError("crash-after-commit")):
            with self.assertRaises(RuntimeError):
                states.set_emergency(
                    self.cfg, self.pool, self.alerter, on=True,
                    log=lambda *_: None, _locked=True)
        self.assertEqual(self.pool.get_setting("automat_state"), states.EMERGENCY)
        self.assertEqual(self.pool.get_setting("emergency_manual"), "1")
        self.assertTrue(self.pool.get_setting("manual_emergency_ref").startswith(
            "manual-emergency-"))

    def test_dns_cleanup_failure_blocks_leave_direct(self):
        self.pool.set_setting("automat_state", states.EMERGENCY)
        with mock.patch.object(states, "_prepare_dns_emergency_exit",
                               return_value={"ok": False, "action": "deferred"}), \
                mock.patch.object(states, "emergency_off") as emergency_off, \
                mock.patch.object(states, "_close_dns_incident") as close:
            ok = states._leave_direct(
                self.cfg, self.pool, self.alerter,
                {"ok": True, "egress_ip": "203.0.113.9"},
                lambda *_: None, "auto", states.EMERGENCY)
        self.assertFalse(ok)
        emergency_off.assert_not_called()
        close.assert_not_called()
        self.assertEqual(self.pool.get_setting("automat_state"), states.EMERGENCY)

    def test_successful_leave_orders_dns_route_and_incident_close(self):
        self.pool.set_setting("automat_state", states.EMERGENCY)
        order = []
        with mock.patch.object(
                states, "_prepare_dns_emergency_exit",
                side_effect=lambda *_a, **_kw: order.append("dns") or {"ok": True}), \
                mock.patch.object(
                    states, "emergency_off",
                    side_effect=lambda *_a, **_kw: order.append("route") or True), \
                mock.patch.object(
                    states, "_close_dns_incident",
                    side_effect=lambda *_a, **_kw: order.append("close") or {}), \
                mock.patch.object(states.apply_mod, "load_json", return_value={}), \
                mock.patch.object(states.apply_mod, "current_upstream", return_value="192.0.2.8"):
            ok = states._leave_direct(
                self.cfg, self.pool, self.alerter,
                {"ok": True, "egress_ip": "203.0.113.9", "exit_cc": "fi"},
                lambda *_: None, "auto", states.EMERGENCY)
        self.assertTrue(ok)
        self.assertEqual(order, ["dns", "route", "close"])

    def test_leave_direct_closes_dns_and_publishes_ok_before_log_crash(self):
        self.pool.set_settings({"automat_state": states.EMERGENCY,
                                "dns_incident_id": "dns-exit",
                                "dns_recovery_exhausted": "1"})
        self.pool.set_dns_state(
            phase="active_proxy", incident_id="dns-exit", active_scope="all",
            active_slot="cloudflare-proxy", active_kind="node_wide_automatic")
        with mock.patch.object(states, "_prepare_dns_emergency_exit",
                               return_value={"ok": True}), \
             mock.patch.object(states, "emergency_off", return_value=True), \
             mock.patch.object(self.pool, "log_event",
                               side_effect=RuntimeError("crash-after-commit")):
            with self.assertRaises(RuntimeError):
                states._leave_direct(
                    self.cfg, self.pool, self.alerter,
                    {"ok": True, "egress_ip": "203.0.113.9", "exit_cc": "fi"},
                    lambda *_: None, "auto", states.EMERGENCY)
        self.assertEqual(self.pool.get_setting("automat_state"), states.OK)
        self.assertIsNone(self.pool.get_setting("dns_incident_id"))
        self.assertEqual(self.pool.dns_state()["phase"], "idle")

    def test_explicit_apply_uses_common_lock_and_respects_dns_failure(self):
        self.pool.set_setting("automat_state", states.EMERGENCY)
        lock = mock.MagicMock()
        lock.return_value.__enter__.return_value = lock
        with mock.patch.object(states.apply_mod, "Flock", lock), \
                mock.patch.object(states, "_prepare_dns_emergency_exit",
                                  return_value={"ok": False, "action": "failed"}), \
                mock.patch.object(states, "emergency_off") as emergency_off:
            result = states.finish_explicit_apply(
                self.cfg, self.pool, "proxy:1", "192.0.2.9", source="manual",
                log=lambda *_: None)
        lock.assert_called_once_with(self.cfg["lock"])
        emergency_off.assert_not_called()
        self.assertFalse(result["ok"])
        self.assertEqual(self.pool.get_setting("automat_state"), states.EMERGENCY)

    def test_explicit_apply_exit_is_atomic_before_log_crash(self):
        self.pool.set_settings({"automat_state": states.EMERGENCY,
                                "dns_incident_id": "dns-apply",
                                "dns_recovery_exhausted": "1"})
        self.pool.set_dns_state(
            phase="active_proxy", incident_id="dns-apply", active_scope="all",
            active_slot="cloudflare-proxy", active_kind="node_wide_automatic")
        with mock.patch.object(states, "_prepare_dns_emergency_exit",
                               return_value={"ok": True}), \
             mock.patch.object(states, "emergency_off", return_value=True), \
             mock.patch.object(self.pool, "log_event",
                               side_effect=RuntimeError("crash-after-commit")):
            with self.assertRaises(RuntimeError):
                states.finish_explicit_apply(
                    self.cfg, self.pool, "proxy:1", "192.0.2.9",
                    source="manual", log=lambda *_: None, _locked=True)
        self.assertEqual(self.pool.get_setting("automat_state"), states.OK)
        self.assertIsNone(self.pool.get_setting("dns_incident_id"))
        self.assertEqual(self.pool.dns_state()["phase"], "idle")

    def test_manual_off_keeps_sticky_emergency_when_dns_cleanup_fails(self):
        self.pool.set_settings({"automat_state": states.EMERGENCY,
                                "emergency_manual": "1"})
        with mock.patch.object(states, "_prepare_dns_emergency_exit",
                               return_value={"ok": False, "action": "failed"}), \
                mock.patch.object(states, "emergency_off") as emergency_off:
            result = states.set_emergency(
                self.cfg, self.pool, self.alerter, on=False,
                log=lambda *_: None, _locked=True)
        self.assertFalse(result["ok"])
        emergency_off.assert_not_called()
        self.assertEqual(self.pool.get_setting("automat_state"), states.EMERGENCY)
        self.assertEqual(self.pool.get_setting("emergency_manual"), "1")

    def test_manual_off_restores_direct_and_dns_when_normal_verify_fails(self):
        self.pool.set_settings({"automat_state": states.EMERGENCY,
                                "emergency_manual": "1",
                                "emergency_since": "2026-09-06 10:00:00"})
        failed = {"ok": False, "why": "no-ip", "egress_ip": None,
                  "exit_cc": None}
        order = []
        with mock.patch.object(states.os, "name", "posix"), \
                mock.patch.object(states, "_prepare_dns_emergency_exit",
                                  side_effect=lambda *_a, **_k:
                                  order.append("dns-off") or {"ok": True}), \
                mock.patch.object(states, "emergency_off",
                                  side_effect=lambda *_a, **_k:
                                  order.append("route-off") or True), \
                mock.patch.object(states.apply_mod, "verify_egress",
                                  return_value=failed), \
                mock.patch.object(states, "emergency_on",
                                  side_effect=lambda *_a, **_k:
                                  order.append("route-on") or True), \
                mock.patch.object(states, "_restore_dns_after_exit_failure",
                                  side_effect=lambda *_a, **_k:
                                  order.append("dns-on") or {"ok": True}), \
                mock.patch.object(states, "_close_dns_incident") as close:
            result = states.set_emergency(
                self.cfg, self.pool, self.alerter, on=False,
                log=lambda *_: None, _locked=True)
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], states.EMERGENCY)
        self.assertEqual(order, ["dns-off", "route-off", "route-on", "dns-on"])
        close.assert_not_called()
        self.assertEqual(self.pool.get_setting("emergency_manual"), "1")

    def test_manual_off_closes_dns_and_publishes_ok_before_log_crash(self):
        self.pool.set_settings({"automat_state": states.EMERGENCY,
                                "emergency_manual": "1",
                                "manual_emergency_ref": "manual-ref",
                                "dns_incident_id": "dns-manual"})
        self.pool.set_dns_state(
            phase="active_proxy", incident_id="dns-manual", active_scope="all",
            active_slot="cloudflare-proxy", active_kind="node_wide_manual",
            manual_emergency_ref="manual-ref")
        with mock.patch.object(states, "_prepare_dns_emergency_exit",
                               return_value={"ok": True}), \
             mock.patch.object(states, "emergency_off", return_value=True), \
             mock.patch.object(self.pool, "log_event",
                               side_effect=RuntimeError("crash-after-commit")):
            with self.assertRaises(RuntimeError):
                states.set_emergency(
                    self.cfg, self.pool, self.alerter, on=False,
                    log=lambda *_: None, _locked=True)
        self.assertEqual(self.pool.get_setting("automat_state"), states.OK)
        self.assertIsNone(self.pool.get_setting("dns_incident_id"))
        self.assertEqual(self.pool.dns_state()["phase"], "idle")


class HeartbeatPauseContractCase(unittest.TestCase):
    def _pool(self, phase):
        p = mock.Mock()
        values = {"automat_frozen": "1", "automat_state": states.EMERGENCY,
                  "emergency_manual": None}
        p.get_setting.side_effect = lambda key: values.get(key)
        p.dns_state.return_value = {"phase": phase}
        return p

    def _run(self, phase):
        pool = self._pool(phase)
        tick = mock.Mock()
        patches = (
            mock.patch.object(agent, "load_secrets", return_value=({}, None)),
            mock.patch.object(agent, "make_providers", return_value={}),
            mock.patch.object(agent, "open_pool", return_value=pool),
            mock.patch.object(agent, "_make_alerter", return_value=_NullAlerter()),
            mock.patch.object(agent.dns_rescue_mod, "reconcile", return_value={}),
            mock.patch.object(agent.dns_rescue_mod, "automatic_tick", tick),
            mock.patch.object(agent.states_mod, "heartbeat_check",
                              return_value={"stale": False, "age_h": None}),
            mock.patch.object(agent.states_mod, "reconcile_desired_selection",
                              return_value={"action": "up-to-date"}),
        )
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patches[5], patches[6], patches[7]:
            rc = agent.cmd_heartbeat_check({}, SimpleNamespace())
        return rc, tick

    def test_pause_blocks_new_heartbeat_activation(self):
        rc, tick = self._run("idle")
        self.assertEqual(rc, 0)
        tick.assert_not_called()

    def test_pause_still_services_active_fail_open(self):
        rc, tick = self._run("active_direct")
        self.assertEqual(rc, 0)
        tick.assert_called_once()


class WatchdogExitContractCase(unittest.TestCase):
    def test_disabled_or_ineligible_tick_is_successful_noop(self):
        pool = mock.Mock()
        pool.get_setting.side_effect = lambda key: {
            "automat_state": states.OK, "emergency_manual": None}.get(key)
        safe_status = {"state": {"active_scope": None}, "coverage": {},
                       "unfinished": []}
        with mock.patch.object(agent, "open_pool", return_value=pool), \
                mock.patch.object(agent.dns_rescue_mod, "reconcile", return_value={}), \
                mock.patch.object(agent.dns_rescue_mod, "automatic_tick",
                                  return_value={"ok": False, "action": "ineligible"}), \
                mock.patch.object(agent.dns_rescue_mod, "status",
                                  return_value=safe_status), \
                mock.patch("builtins.print"):
            rc = agent.cmd_dns_rescue(
                {}, SimpleNamespace(dns_action="tick", scope=None, slot=None))
        self.assertEqual(rc, 0)
        pool.close.assert_called_once()

    def test_watchdog_returns_failure_only_for_unsafe_fail_open_state(self):
        pool = mock.Mock()
        pool.get_setting.return_value = None
        with mock.patch.object(agent, "open_pool", return_value=pool), \
                mock.patch.object(agent.dns_rescue_mod, "reconcile", return_value={}), \
                mock.patch.object(agent.dns_rescue_mod, "automatic_tick",
                                  return_value={"ok": False,
                                                "action": "fail-open-blocked"}), \
                mock.patch.object(agent.dns_rescue_mod, "status", return_value={
                    "state": {"active_scope": "peer"}, "coverage": {},
                    "unfinished": []}), \
                mock.patch("builtins.print"):
            rc = agent.cmd_dns_rescue(
                {}, SimpleNamespace(dns_action="tick", scope=None, slot=None))
        self.assertEqual(rc, 1)

    def test_watchdog_reports_unreconciled_cleanup_as_failure(self):
        pool = mock.Mock()
        pool.get_setting.return_value = None
        with mock.patch.object(agent, "open_pool", return_value=pool), \
                mock.patch.object(agent.dns_rescue_mod, "reconcile", return_value={
                    "phase": "recovering", "last_error": "cleanup:DNSRuntimeError"}), \
                mock.patch.object(agent.dns_rescue_mod, "automatic_tick",
                                  return_value={"ok": False, "action": "ineligible"}), \
                mock.patch.object(agent.dns_rescue_mod, "status", return_value={
                    "state": {"active_scope": None}, "coverage": {},
                    "unfinished": []}), \
                mock.patch("builtins.print"):
            rc = agent.cmd_dns_rescue(
                {}, SimpleNamespace(dns_action="tick", scope=None, slot=None))
        self.assertEqual(rc, 1)

    def test_watchdog_reports_exhausted_boot_compensation_as_failure(self):
        pool = mock.Mock()
        pool.get_setting.return_value = None
        with mock.patch.object(agent, "open_pool", return_value=pool), \
                mock.patch.object(agent.dns_rescue_mod, "reconcile", return_value={
                    "phase": "failed", "last_error": "boot-resume-exhausted"}), \
                mock.patch.object(agent.dns_rescue_mod, "automatic_tick",
                                  return_value={"ok": False,
                                                "action": "ineligible"}), \
                mock.patch.object(agent.dns_rescue_mod, "status", return_value={
                    "state": {"active_scope": None}, "coverage": {},
                    "unfinished": []}), \
                mock.patch("builtins.print"):
            rc = agent.cmd_dns_rescue(
                {}, SimpleNamespace(dns_action="tick", scope=None, slot=None))
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
