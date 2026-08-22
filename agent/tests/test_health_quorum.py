# -*- coding: utf-8 -*-
import unittest
import time
import os
import tempfile
from unittest import mock

import _ctx  # noqa: F401
import health
import pool as pool_mod
import states


NOW = time.time()


def ev(signal, ok, target, **kwargs):
    return health.evidence(signal, ok, target=target, observed_at=NOW,
                           via_proxy=kwargs.pop("via_proxy", True), **kwargs)


class TestHealthQuorum(unittest.TestCase):
    def test_one_external_site_is_not_a_proxy_fault(self):
        decision = health.proxy_fault_decision([
            ev("socks", False, "https://api.ipify.org"),
            ev("http", False, "https://api.ipify.org"),
        ], now=NOW)
        self.assertFalse(decision["proxy_fault"])
        self.assertEqual(decision["reason"], "single-target-or-insufficient")
        self.assertEqual(len(decision["failed_targets"]), 1)

    def test_any_fresh_proxy_path_success_prevents_false_rotation(self):
        decision = health.proxy_fault_decision([
            ev("socks", False, "https://api.ipify.org"),
            ev("http", False, "https://api.ipify.org"),
            ev("http", True, "https://www.gstatic.com/generate_204"),
        ], now=NOW)
        self.assertFalse(decision["proxy_fault"])
        self.assertEqual(decision["reason"], "proxy-path-alive")

    def test_two_independent_targets_confirm_real_failure(self):
        decision = health.proxy_fault_decision([
            ev("socks", False, "https://api.ipify.org"),
            ev("telegram", False, "https://api.telegram.org"),
        ], now=NOW)
        self.assertTrue(decision["proxy_fault"])
        self.assertEqual(decision["reason"], "target-quorum")

    def test_tcp_refusal_is_fast_path_without_quorum(self):
        decision = health.proxy_fault_decision([
            ev("socks", False, "proxy:1080", error_kind="tcp-refused")
        ], now=NOW)
        self.assertTrue(decision["proxy_fault"])
        self.assertTrue(decision["fast_path"])

    def test_working_path_overrides_refusal_from_another_port(self):
        decision = health.proxy_fault_decision([
            ev("socks", False, "proxy:1080", error_kind="tcp-refused"),
            ev("http", True, "https://www.gstatic.com/generate_204"),
        ], now=NOW)
        self.assertFalse(decision["proxy_fault"])
        self.assertEqual(decision["reason"], "proxy-path-alive")

    def test_stale_and_non_proxy_failures_do_not_vote(self):
        old = health.evidence("socks", False, target="a", observed_at=NOW - 61,
                              via_proxy=True)
        decision = health.proxy_fault_decision([
            old, ev("provider_api", False, "provider"),
            ev("geo", False, "geo"), ev("dns", False, "resolver", via_proxy=False),
        ], now=NOW)
        self.assertFalse(decision["proxy_fault"])
        self.assertEqual(decision["fresh_signals"], 3)

    def test_invalid_quorum_config_falls_back(self):
        self.assertEqual(health.quorum_cfg({"health": {
            "quorum_window_seconds": True, "quorum_min_targets": 1}}),
            health.DEFAULT_QUORUM)


class TestRetuneQuorumIntegration(unittest.TestCase):
    row = {"uid": "proxy6:1", "host": "1.1.1.1", "user": "u", "password": "p"}

    def run_retune(self, evidence):
        result = {"ok": False, "disqualified": "no-combo", "evidence": evidence}
        with mock.patch.object(states.apply_mod, "load_json", return_value={}), \
             mock.patch.object(states.apply_mod, "current_upstream", return_value="1.1.1.1"), \
             mock.patch.object(states, "_pool_row_by_host", return_value=self.row), \
             mock.patch.object(states, "_probe", return_value=result):
            return states.try_retune(
                {"singbox_config": "x"}, {}, mock.Mock(get=lambda _uid: None),
                object(), lambda *_: None, "auto")

    def test_single_endpoint_outage_is_held(self):
        result = self.run_retune([
            ev("socks", False, "https://api.ipify.org"),
            ev("http", False, "https://api.ipify.org"),
            ev("http", True, "https://www.gstatic.com/generate_204"),
        ])
        self.assertTrue(result["external_outage"])
        self.assertFalse(result["health_decision"]["proxy_fault"])

    def test_real_multi_target_failure_is_confirmed(self):
        result = self.run_retune([
            ev("socks", False, "https://api.ipify.org"),
            ev("http", False, "https://www.gstatic.com/generate_204"),
        ])
        self.assertTrue(result["proxy_fault_confirmed"])
        self.assertTrue(result["health_decision"]["proxy_fault"])


class TestQuorumRegressions(unittest.TestCase):
    def test_external_outage_does_not_poison_persistent_proxy_health(self):
        with tempfile.TemporaryDirectory() as tmp:
            pool = pool_mod.Pool(os.path.join(tmp, "state.db"), server="test")
            try:
                uid = pool.upsert_proxy({
                    "provider": "proxy6", "ext_id": "1", "ip": "1.1.1.1",
                    "host": "1.1.1.1", "port_http": 8080, "port_socks5": 1080,
                    "user": "u", "password": "p", "country": "fi", "ip_version": 4,
                    "kind": "dedicated", "date_end": None, "descr": ""})
                pool.conn.execute(
                    "UPDATE proxy SET probe_ok=1,fail_count=0,score=120 WHERE uid=?", (uid,))
                pool.conn.commit()
                result = {
                    "ok": False, "disqualified": "no-combo",
                    "evidence": [
                        health.evidence("http", False, target="https://api.ipify.org",
                                        via_proxy=True),
                        health.evidence("http", True,
                                        target="https://www.gstatic.com/generate_204",
                                        via_proxy=True),
                    ]}
                with mock.patch.object(states.apply_mod, "load_json", return_value={}), \
                     mock.patch.object(states.apply_mod, "current_upstream",
                                       return_value="1.1.1.1"), \
                     mock.patch.object(states.probe_mod, "probe", return_value=result):
                    verdict = states.try_retune(
                        {"singbox_config": "x"}, {}, pool, object(), lambda *_: None, "auto")
                row = pool.get(uid)
                self.assertTrue(verdict["external_outage"])
                self.assertEqual((row["probe_ok"], row["fail_count"], row["score"]),
                                 (1, 0, 120.0))
                self.assertEqual(pool.conn.execute(
                    "SELECT COUNT(*) FROM probe_log").fetchone()[0], 0)
            finally:
                pool.close()

    def test_quorum_hold_leaves_direct_mode_consistently(self):
        with tempfile.TemporaryDirectory() as tmp:
            pool = pool_mod.Pool(os.path.join(tmp, "state.db"), server="test")
            try:
                failed = {"ok": False, "egress_ip": None, "exit_cc": None,
                          "why_kind": "no-ip", "evidence": []}
                for previous in (states.EMERGENCY, states.ROTATING):
                    pool.set_setting("automat_state", previous)
                    result = {"state": None, "action": None, "detail": "", "ok": False}
                    with mock.patch.object(states, "reconcile_strategy_override"), \
                         mock.patch.object(states.apply_mod, "load_json", return_value={}), \
                         mock.patch.object(states.apply_mod, "current_upstream",
                                           return_value="1.1.1.1"), \
                         mock.patch.object(states, "net_alive", return_value=(True, "ip", [])), \
                         mock.patch.object(states.apply_mod, "verify_egress",
                                           return_value=failed), \
                         mock.patch.object(states, "singbox_health",
                                           return_value={"ok": True, "active": True,
                                                         "tun0": True}), \
                         mock.patch.object(states, "try_retune", return_value={
                             "ok": False, "external_outage": True,
                             "health_decision": {"reason": "proxy-path-alive",
                                                 "failed_targets": ["ipify"],
                                                 "successful_signals": 1,
                                                 "threshold": 2}}), \
                         mock.patch.object(states, "_leave_direct") as leave, \
                         mock.patch.object(states, "try_rotating") as rotate:
                        answer = states._rotate_locked(
                            {}, {}, pool, mock.Mock(), "watchdog", "auto",
                            lambda *_: None, result, previous)
                    self.assertEqual((answer["state"], answer["action"]),
                                     (states.DEGRADED, "quorum-held"))
                    leave.assert_called_once()
                    rotate.assert_not_called()
            finally:
                pool.close()

    def test_net_alive_preserves_dns_failure_as_separate_signal(self):
        responses = [(6, "000"), (0, "200")]
        with mock.patch.object(states.os, "name", "posix"), \
             mock.patch.object(states.apply_mod, "run_cmd", side_effect=responses):
            alive, via, evidence = states.net_alive(
                {"net_check_urls": ["https://example.test", "https://1.1.1.1"]},
                lambda *_: None, with_evidence=True)
        self.assertTrue(alive)
        self.assertEqual(via, "https://1.1.1.1")
        self.assertTrue(any(item["signal"] == "dns" and not item["ok"]
                            for item in evidence))
        self.assertTrue(any(item["signal"] == "server_network" and item["ok"]
                            for item in evidence))


if __name__ == "__main__":
    unittest.main()
