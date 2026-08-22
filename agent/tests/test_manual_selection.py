# -*- coding: utf-8 -*-
"""AUTO/MANUAL: ручной канал держится до подтверждённого отказа."""
import json
import os
import tempfile
import unittest
from unittest import mock

import _ctx  # noqa: F401
import pool as pool_mod
import states


class _Alerter:
    def __getattr__(self, _name):
        return lambda *a, **kw: None


def _verify(ok, why_kind=None):
    return {"ok": ok, "egress_ip": "203.0.113.10" if ok else None,
            "exit_cc": "lv" if ok else None, "tg_code": "200" if ok else "000",
            "why": "" if ok else "dead", "why_kind": why_kind}


class TestSelectionMode(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "state.db")
        self.pool = pool_mod.Pool(self.db, server="test")
        self.cfg_path = os.path.join(self.tmp.name, "config.json")
        self.sb_path = os.path.join(self.tmp.name, "singbox.json")
        with open(self.cfg_path, "w", encoding="utf-8") as f:
            json.dump({"countries": {"strategy": "reputation"}}, f)
        with open(self.sb_path, "w", encoding="utf-8") as f:
            json.dump({"outbounds": [{"tag": "socks-out", "type": "socks",
                                      "server": "10.0.0.1", "server_port": 1080}]}, f)
        self.cfg = {"_source": self.cfg_path, "singbox_config": self.sb_path,
                    "countries": {"strategy": "reputation"}}
        self.uid = self.pool.upsert_proxy({
            "provider": "proxy6", "ext_id": "1", "ip": "10.0.0.1", "host": "10.0.0.1",
            "port_http": 8080, "port_socks5": 1080, "user": "u", "password": "p",
            "country": "lv", "ip_version": 4, "kind": "dedicated",
            "date_end": None, "descr": ""})
        self.alerter = _Alerter()

    def tearDown(self):
        self.pool.close()
        self.tmp.cleanup()

    def pin(self):
        return states.set_manual_selection(self.pool, self.uid, "10.0.0.1")

    def mode(self):
        return states.selection_state(self.pool, self.cfg, "10.0.0.1")

    def cycle(self, state_before=states.OK):
        return states._rotate_locked(
            self.cfg, {}, self.pool, self.alerter, "watchdog", "auto",
            lambda *a: None, {}, state_before)

    def test_old_database_defaults_to_auto_speed_policy(self):
        self.assertEqual(self.mode()["mode"], "auto")
        self.assertEqual(states.MANUAL_FALLBACK_STRATEGY, "speed")

    def test_manual_pin_is_atomic_and_auto_clears_all_fields(self):
        st = self.pin()
        self.assertEqual(st["mode"], "manual")
        self.assertEqual(st["manual_uid"], self.uid)
        states.set_auto_selection(self.pool, self.cfg, strategy="balanced")
        st = self.mode()
        self.assertEqual(st["mode"], "auto")
        self.assertIsNone(st["manual_uid"])
        self.assertIsNone(st["manual_host"])
        self.assertIsNone(st["manual_since"])

    def test_healthy_cycle_only_watches_manual_channel(self):
        self.pin()
        with mock.patch.object(states, "net_alive", return_value=(True, "x")), \
             mock.patch.object(states.apply_mod, "verify_egress", return_value=_verify(True)), \
             mock.patch.object(states, "singbox_health", return_value={"ok": True, "active": True, "tun0": True}):
            r = self.cycle()
        self.assertEqual(r["action"], "manual-watch")
        self.assertEqual(self.mode()["mode"], "manual")
        with open(self.cfg_path, encoding="utf-8") as f:
            self.assertEqual(json.load(f)["countries"]["strategy"], "reputation")

    def test_server_network_failure_does_not_release_manual(self):
        self.pin()
        with mock.patch.object(states, "net_alive", return_value=(False, None)), \
             mock.patch.object(states.apply_mod, "verify_egress", return_value=_verify(False)), \
             mock.patch.object(states, "singbox_health", return_value={"ok": True, "active": True, "tun0": True}):
            r = self.cycle()
        self.assertEqual(r["action"], "frozen_net")
        self.assertEqual(self.mode()["mode"], "manual")

    def test_single_flap_recovered_by_recheck_keeps_manual(self):
        self.pin()
        with mock.patch.object(states, "net_alive", return_value=(True, "x")), \
             mock.patch.object(states.apply_mod, "verify_egress",
                               side_effect=[_verify(False), _verify(True)]), \
             mock.patch.object(states, "singbox_health", return_value={"ok": True, "active": True, "tun0": True}), \
             mock.patch.object(states, "try_retune", return_value={"ok": False}), \
             mock.patch.object(states.time, "sleep"):
            r = self.cycle()
        self.assertEqual(r["action"], "flap")
        self.assertEqual(self.mode()["mode"], "manual")

    def test_confirmed_proxy_failure_releases_to_speed_before_ranking(self):
        self.pin()
        seen = []

        def rotating(cfg, *args, **kwargs):
            seen.append(cfg["countries"]["strategy"])
            return {"ok": True, "verify": _verify(True), "detail": "ok"}

        with mock.patch.object(states, "net_alive", return_value=(True, "x")), \
             mock.patch.object(states.apply_mod, "verify_egress", return_value=_verify(False)), \
             mock.patch.object(states, "singbox_health", return_value={"ok": True, "active": True, "tun0": True}), \
             mock.patch.object(states, "try_retune", return_value={"ok": False}), \
             mock.patch.object(states, "try_rotating", side_effect=rotating), \
             mock.patch.object(states, "ensure_reserve", return_value={"ok": True}), \
             mock.patch.object(states, "emergency_off"):
            r = self.cycle(state_before=states.ROTATING)
        self.assertTrue(r["manual_released"])
        self.assertEqual(r["fallback_strategy"], "speed")
        self.assertEqual(seen, ["speed"], "кандидаты обязаны ранжироваться уже по speed")
        self.assertEqual(self.mode()["mode"], "auto")
        with open(self.cfg_path, encoding="utf-8") as f:
            self.assertEqual(json.load(f)["countries"]["strategy"], "speed")

    def test_config_write_failure_does_not_block_failover_and_is_retried(self):
        self.pin()
        with mock.patch.object(states.config_store, "save_country_strategy",
                               side_effect=OSError("read-only")):
            r = states.release_manual_on_fault(self.cfg, self.pool, log=lambda *a: None)
        self.assertTrue(r["released"])
        self.assertIn("read-only", r["persist_error"])
        self.assertEqual(self.cfg["countries"]["strategy"], "speed")
        self.assertEqual(self.pool.get_setting("selection_strategy_override"), "speed")
        self.assertEqual(self.mode()["mode"], "auto")

    def test_explicit_apply_source_controls_mode(self):
        states.finish_explicit_apply(self.cfg, self.pool, self.uid, "10.0.0.1",
                                     _verify(True), source="strategy")
        self.assertEqual(self.mode()["mode"], "auto")
        states.finish_explicit_apply(self.cfg, self.pool, self.uid, "10.0.0.1",
                                     _verify(True), source="manual")
        self.assertEqual(self.mode()["mode"], "manual")

    def test_manual_mode_blocks_proactive_reserve_purchase(self):
        self.pin()
        with mock.patch.object(states.apply_mod, "load_json") as load:
            r = states.ensure_reserve(self.cfg, {}, self.pool, self.alerter,
                                      lambda *a: None, "auto")
        self.assertEqual(r["skipped"], "manual-selection")
        load.assert_not_called()

    def test_removed_provider_key_does_not_bypass_manual_pin(self):
        self.pin()
        r = states.switch_from_provider(self.cfg, {}, self.pool, self.alerter,
                                        "proxy6", log=lambda *a: None)
        self.assertTrue(r["ok"])
        self.assertTrue(r["manual"])
        self.assertFalse(r["switched"])


if __name__ == "__main__":
    unittest.main()
