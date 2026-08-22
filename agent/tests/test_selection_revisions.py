# -*- coding: utf-8 -*-
"""P0 desired/applied selection revision и постоянный reconciler."""
import json
import os
import tempfile
import types
import unittest
from unittest import mock

import _ctx
import pool as pool_mod
import states
from webpanel import server


class TestSelectionRevisionState(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "state.db")
        self.pool = pool_mod.Pool(self.db, server="test")
        self.cfg = {"countries": {"strategy": "speed"}}

    def tearDown(self):
        self.pool.close()
        self.tmp.cleanup()

    def test_legacy_database_starts_converged_at_zero(self):
        revision = states.selection_revision_state(self.pool, self.cfg)
        self.assertEqual((revision["desired"], revision["applied"], revision["pending"]),
                         (0, 0, False))
        self.assertEqual(revision["kind"], "strategy")

    def test_manual_success_advances_desired_and_applied_together(self):
        states.set_manual_selection(self.pool, "proxy6:a", "1.1.1.1")
        one = states.selection_revision_state(self.pool, self.cfg)
        self.assertEqual((one["desired"], one["applied"], one["pending"]), (1, 1, False))
        self.assertEqual(one["payload"], {"host": "1.1.1.1", "uid": "proxy6:a"})
        states.set_manual_selection(self.pool, "proxy6:a", "1.1.1.1")
        two = states.selection_revision_state(self.pool, self.cfg)
        self.assertEqual((two["desired"], two["applied"]), (2, 2),
                         "повторное «В бой» — новое явное намерение владельца")

    def test_strategy_clicks_are_monotonic_and_stale_worker_cannot_ack_latest(self):
        one = states.request_strategy_selection(self.pool, self.cfg, "speed")
        two = states.request_strategy_selection(self.pool, self.cfg, "reputation")
        self.assertEqual((one, two), (1, 2))
        self.assertFalse(states.mark_selection_applied(self.pool, one),
                         "worker ревизии 1 не вправе подтвердить ревизию 2")
        pending = states.selection_revision_state(self.pool, self.cfg)
        self.assertEqual((pending["desired"], pending["applied"], pending["pending"]),
                         (2, 0, True))
        self.assertTrue(states.mark_selection_applied(self.pool, two))
        self.assertFalse(states.selection_revision_state(self.pool, self.cfg)["pending"])

    def test_pending_revision_survives_reopen(self):
        states.request_strategy_selection(self.pool, self.cfg, "balanced")
        self.pool.close()
        self.pool = pool_mod.Pool(self.db, server="test")
        revision = states.selection_revision_state(self.pool, self.cfg)
        self.assertEqual((revision["desired"], revision["applied"], revision["pending"]),
                         (1, 0, True))
        self.assertEqual(revision["payload"]["strategy"], "balanced")

    def test_intent_and_event_roll_back_together(self):
        self.pool.conn.execute(
            "CREATE TRIGGER deny_selection_event BEFORE INSERT ON event"
            " WHEN NEW.action='selection-intent' BEGIN SELECT RAISE(ABORT,'event denied'); END")
        self.pool.conn.commit()
        with self.assertRaises(Exception):
            states.request_strategy_selection(self.pool, self.cfg, "speed")
        self.assertIsNone(self.pool.get_setting("desired_selection_revision"))
        self.assertEqual(self.pool.conn.execute(
            "SELECT COUNT(*) FROM event WHERE action='selection-intent'").fetchone()[0], 0)

    def test_mark_applied_is_idempotent_without_duplicate_event(self):
        revision = states.request_strategy_selection(self.pool, self.cfg, "speed")
        self.assertTrue(states.mark_selection_applied(self.pool, revision))
        self.assertTrue(states.mark_selection_applied(self.pool, revision))
        count = self.pool.conn.execute(
            "SELECT COUNT(*) FROM event WHERE action='selection-reconciled'").fetchone()[0]
        self.assertEqual(count, 1)

    def test_stale_config_writer_cannot_clear_latest_override(self):
        one = states.request_strategy_selection(
            self.pool, self.cfg, "speed", pending_config=True)
        two = states.request_strategy_selection(
            self.pool, self.cfg, "reputation", pending_config=True)
        self.assertFalse(self.pool.clear_strategy_override(one, "speed"))
        self.assertEqual(self.pool.get_setting("selection_strategy_override"), "reputation")
        self.assertTrue(self.pool.clear_strategy_override(two, "reputation"))
        self.assertIsNone(self.pool.get_setting("selection_strategy_override"))

    def test_old_strategy_finish_cannot_erase_new_config_repair(self):
        states.request_strategy_selection(self.pool, self.cfg, "speed")
        latest = states.request_strategy_selection(
            self.pool, self.cfg, "reputation", pending_config=True)
        states.finish_explicit_apply(
            self.cfg, self.pool, "proxy6:old", "1.1.1.1", source="strategy")
        revision = states.selection_revision_state(self.pool, self.cfg)
        self.assertEqual(revision["desired"], latest)
        self.assertTrue(revision["pending"])
        self.assertEqual(self.pool.get_setting("selection_strategy_override"), "reputation")


class TestSelectionReconciler(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "state.db")
        self.sb = os.path.join(self.tmp.name, "singbox.json")
        self.config_path = os.path.join(self.tmp.name, "config.json")
        with open(self.sb, "w", encoding="utf-8") as f:
            json.dump({"outbounds": [{"tag": "socks-out", "server": "10.0.0.1"}]}, f)
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump({"countries": {"strategy": "speed"}}, f)
        self.cfg = {"_source": self.config_path, "singbox_config": self.sb,
                    "countries": {"strategy": "speed"}}
        self.pool = pool_mod.Pool(self.db, server="test")

    def tearDown(self):
        self.pool.close()
        self.tmp.cleanup()

    def add_current(self):
        uid = self.pool.upsert_proxy({
            "provider": "proxy6", "ext_id": "cur", "ip": "10.0.0.1",
            "host": "10.0.0.1", "port_http": 8080, "port_socks5": 1080,
            "user": "u", "password": "p", "country": "de", "ip_version": 4,
            "kind": "dedicated", "date_end": None, "descr": ""})
        self.pool.conn.execute(
            "UPDATE proxy SET probe_ok=1,score=150,latency_ms=50,exit_cc='de',"
            " last_probe_at=? WHERE uid=?",
            (states._now_iso(), uid))
        self.pool.conn.commit()
        return uid

    def test_stable_current_marks_pending_revision_applied(self):
        self.add_current()
        revision = states.request_strategy_selection(self.pool, self.cfg, "speed")
        result = states._converge_strategy_locked(
            self.cfg, {"proxy6": object()}, self.pool, log=lambda *_: None)
        self.assertEqual(result["action"], "stable")
        self.assertEqual(states.selection_revision_state(self.pool, self.cfg)["applied"], revision)

    def test_read_only_config_cannot_be_acknowledged_as_applied(self):
        self.add_current()
        revision = states.request_strategy_selection(
            self.pool, self.cfg, "reputation", pending_config=True)
        with mock.patch.object(states.config_store, "save_country_strategy",
                               side_effect=OSError("read-only")):
            result = states._converge_strategy_locked(
                self.cfg, {"proxy6": object()}, self.pool, log=lambda *_: None)
        self.assertEqual(result["action"], "stable")
        state = states.selection_revision_state(self.pool, self.cfg)
        self.assertEqual((state["desired"], state["applied"], state["pending"]),
                         (revision, 0, True))
        self.assertEqual(self.pool.get_setting("selection_strategy_override"), "reputation")

    def test_reconciler_calls_convergence_only_when_pending(self):
        with mock.patch.object(states, "converge_strategy", return_value={"ok": True,
                               "action": "stable"}) as converge, \
             mock.patch.object(states.os, "name", "posix"):
            current = states.reconcile_desired_selection(
                self.cfg, {}, self.pool, log=lambda *_: None)
            converge.assert_not_called()
            states.request_strategy_selection(self.pool, self.cfg, "speed")
            pending = states.reconcile_desired_selection(
                self.cfg, {}, self.pool, log=lambda *_: None)
            converge.assert_called_once()
        self.assertEqual(current["action"], "up-to-date")
        self.assertEqual(pending["action"], "stable")

    def test_panel_startup_requeues_pending_revision_after_reboot(self):
        revision = states.request_strategy_selection(self.pool, self.cfg, "speed")
        fake = types.SimpleNamespace(pool=self.pool, cfg=self.cfg)
        saved = server.APP
        server.APP = fake
        try:
            with mock.patch.object(server, "_strategy_switch_kick",
                                   return_value=(True, "")) as kick:
                self.assertTrue(server._reconcile_selection_on_startup())
            kick.assert_called_once_with(None)
        finally:
            server.APP = saved
        state = states.selection_revision_state(self.pool, self.cfg)
        self.assertEqual((state["desired"], state["applied"], state["pending"]),
                         (revision, 0, True), "enqueue не выдаётся за фактическое применение")

    def test_manual_pending_is_never_auto_applied_to_different_live(self):
        self.pool.request_selection_intent(
            "manual", {"uid": "proxy6:x", "host": "10.0.0.9"},
            {"selection_mode": states.SELECTION_MANUAL, "manual_uid": "proxy6:x",
             "manual_host": "10.0.0.9"}, actor="user", applied=False)
        result = states.reconcile_desired_selection(
            self.cfg, {}, self.pool, log=lambda *_: None)
        self.assertEqual(result["action"], "manual-pending")
        self.assertTrue(states.selection_revision_state(self.pool, self.cfg)["pending"])


if __name__ == "__main__":
    unittest.main()
