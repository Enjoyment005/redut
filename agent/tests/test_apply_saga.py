# -*- coding: utf-8 -*-
"""P0 saga: фазы реального apply/rollback и recovery после kill-point."""
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

import _ctx
import apply as apply_mod
import pool as pool_mod
import states as states_mod


def config_for(host):
    return {
        "outbounds": [
            {"type": "socks", "tag": "socks-out", "server": host,
             "server_port": 1080, "username": "u", "password": "p", "version": "5"},
            {"type": "http", "tag": "http-tg", "server": host,
             "server_port": 8080, "username": "u", "password": "p"},
        ],
        "route": {"rules": [], "final": "socks-out"},
    }


class TestApplySaga(unittest.TestCase):
    OLD = "1.1.1.1"
    NEW = "2.2.2.2"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.live = os.path.join(self.tmp.name, "config.json")
        self.stage = os.path.join(self.tmp.name, "stage.json")
        self.ring = os.path.join(self.tmp.name, "ring")
        self.db = os.path.join(self.tmp.name, "state.db")
        self.write(self.live, config_for(self.OLD))
        self.pool = pool_mod.Pool(self.db, server="test")
        self.cfg = {"singbox_config": self.live, "stage_path": self.stage,
                    "ring": self.ring, "singbox_bin": "sing-box",
                    "boot_script": os.path.join(self.tmp.name, "missing-boot.sh"),
                    "gw": None, "wan": None, "lock": os.path.join(self.tmp.name, "lock")}
        self.row = {"uid": "proxy6:new", "host": self.NEW, "ip": self.NEW,
                    "user": "u", "password": "p"}
        self.probe = {"ok": True, "socks_port": 1080, "http_port": 8080}
        self.ok_verify = {"ok": True, "egress_ip": self.NEW, "exit_cc": "de",
                          "tg_code": "200", "why": ""}

    def tearDown(self):
        self.pool.close()
        self.tmp.cleanup()

    @staticmethod
    def write(path, value):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(value, f, sort_keys=True)

    def operations(self):
        return [dict(r) for r in self.pool.conn.execute("SELECT * FROM operation ORDER BY rowid")]

    def system_ok(self, verify=None):
        return mock.patch.multiple(
            apply_mod, singbox_check=mock.DEFAULT, restart_singbox=mock.DEFAULT,
            wait_tun0=mock.DEFAULT, verify_egress=mock.DEFAULT,
            antiloop_replace=mock.DEFAULT, patch_boot_script=mock.DEFAULT)

    def test_successful_apply_records_full_lifecycle(self):
        with self.system_ok() as m:
            m["singbox_check"].return_value = (0, "")
            m["restart_singbox"].return_value = True
            m["wait_tun0"].return_value = True
            m["verify_egress"].return_value = self.ok_verify
            m["antiloop_replace"].return_value = "ok"
            m["patch_boot_script"].return_value = False
            result = apply_mod.apply_candidate(
                self.cfg, self.row, self.probe, log=lambda *_: None,
                pool=self.pool, requested_by="test", idempotency_key="apply:success")
            apply_mod.commit_operation(self.pool, result)
        op = self.pool.get_operation(operation_id=result["operation_id"])
        self.assertEqual(op["phase"], "committed")
        self.assertEqual(apply_mod.current_upstream(apply_mod.load_json(self.live)), self.NEW)
        self.assertEqual(op["after_checksum"], apply_mod.file_checksum(self.live))
        phases = [r[0] for r in self.pool.conn.execute(
            "SELECT result FROM event WHERE action='operation' ORDER BY id")]
        self.assertEqual(phases, ["planned", "probing", "staged", "applied",
                                  "verifying", "committed"])

    def test_commit_is_deferred_until_caller_state_is_written(self):
        with self.system_ok() as m:
            m["singbox_check"].return_value = (0, "")
            m["restart_singbox"].return_value = True
            m["wait_tun0"].return_value = True
            m["verify_egress"].return_value = self.ok_verify
            m["antiloop_replace"].return_value = "ok"
            m["patch_boot_script"].return_value = False
            result = apply_mod.apply_candidate(
                self.cfg, self.row, self.probe, log=lambda *_: None,
                pool=self.pool, requested_by="test", idempotency_key="apply:deferred",
                selection_source="manual")
        self.assertEqual(self.pool.get_operation(operation_id=result["operation_id"])["phase"],
                         "verifying")
        self.pool.set_setting("caller_state", "done")
        apply_mod.commit_operation(self.pool, result)
        self.assertEqual(self.pool.get_operation(operation_id=result["operation_id"])["phase"],
                         "committed")

    def test_unique_stage_paths_do_not_cross_dry_run_and_live(self):
        one = apply_mod.stage_candidate(self.cfg, self.row, self.probe)[0]
        two = apply_mod.stage_candidate(self.cfg, dict(self.row, host="3.3.3.3"), self.probe)[0]
        self.addCleanup(lambda: os.path.exists(one) and os.unlink(one))
        self.addCleanup(lambda: os.path.exists(two) and os.unlink(two))
        self.assertNotEqual(one, two)
        self.assertEqual(apply_mod.current_upstream(apply_mod.load_json(one)), self.NEW)
        self.assertEqual(apply_mod.current_upstream(apply_mod.load_json(two)), "3.3.3.3")

    def test_db_error_after_replace_leaves_operation_recoverable(self):
        original_transition = self.pool.transition_operation
        failed = {"done": False}

        def transient(operation_id, phase, **kwargs):
            if phase == "applied" and not failed["done"]:
                failed["done"] = True
                raise __import__("sqlite3").OperationalError("disk busy")
            return original_transition(operation_id, phase, **kwargs)

        with self.system_ok() as m, mock.patch.object(
                self.pool, "transition_operation", side_effect=transient):
            m["singbox_check"].return_value = (0, "")
            m["restart_singbox"].return_value = True
            m["wait_tun0"].return_value = True
            m["verify_egress"].return_value = self.ok_verify
            m["antiloop_replace"].return_value = "ok"
            m["patch_boot_script"].return_value = False
            with self.assertRaisesRegex(__import__("sqlite3").OperationalError, "disk busy"):
                apply_mod.apply_candidate(
                    self.cfg, self.row, self.probe, log=lambda *_: None,
                    pool=self.pool, requested_by="test", idempotency_key="apply:db-fail")
        op = self.pool.unfinished_operations()[0]
        self.assertEqual(op["phase"], "staged")
        self.assertEqual(apply_mod.current_upstream(apply_mod.load_json(self.live)), self.NEW)

    def test_atomic_restore_failure_never_truncates_live(self):
        src = os.path.join(self.tmp.name, "restore.json")
        self.write(src, config_for(self.NEW))
        before = apply_mod.file_checksum(self.live)

        def partial(_source, target, length=None):
            target.write(b"{partial")
            raise OSError("kill point")

        with mock.patch.object(apply_mod.shutil, "copyfileobj", side_effect=partial):
            with self.assertRaises(OSError):
                apply_mod.atomic_copy_replace(src, self.live)
        self.assertEqual(apply_mod.file_checksum(self.live), before)

    def test_unconfirmed_compensation_stays_unfinished(self):
        bad = {"ok": False, "egress_ip": None, "exit_cc": None,
               "tg_code": "000", "why": "dead"}
        with self.system_ok() as m:
            m["singbox_check"].return_value = (0, "")
            m["restart_singbox"].side_effect = [True, False]
            m["wait_tun0"].side_effect = [True, False]
            m["verify_egress"].side_effect = [bad, bad]
            m["antiloop_replace"].return_value = "ok"
            m["patch_boot_script"].return_value = False
            with self.assertRaises(apply_mod.ApplyError):
                apply_mod.apply_candidate(
                    self.cfg, self.row, self.probe, log=lambda *_: None,
                    pool=self.pool, requested_by="test", idempotency_key="apply:uncertain")
        self.assertEqual(self.pool.unfinished_operations()[0]["phase"], "verifying")

    def test_explicit_rollback_restart_failure_has_before_backup_and_is_unfinished(self):
        os.makedirs(self.ring)
        target = os.path.join(self.ring, "20260822-120001.json")
        self.write(target, config_for(self.NEW))
        before = apply_mod.file_checksum(self.live)
        with self.system_ok() as m:
            m["singbox_check"].return_value = (0, "")
            m["restart_singbox"].return_value = False
            m["wait_tun0"].return_value = False
            m["verify_egress"].return_value = self.ok_verify
            m["antiloop_replace"].return_value = "ok"
            m["patch_boot_script"].return_value = False
            with self.assertRaises(apply_mod.ApplyError):
                apply_mod.rollback_from_ring(
                    self.cfg, backup_path=target, log=lambda *_: None,
                    pool=self.pool, requested_by="test", idempotency_key="rollback:restart-fail")
        op = self.pool.unfinished_operations()[0]
        self.assertEqual(op["phase"], "applied")
        self.assertIsNotNone(apply_mod.backup_by_checksum(self.ring, before))

    def test_exact_retune_retry_recovers_instead_of_failing_operation(self):
        row = dict(self.row, host=self.OLD, ip=self.OLD)
        probe = dict(self.probe, socks_port=1099, http_port=8099)
        desired = {"kind": "apply", "uid": row["uid"], "from_host": self.OLD,
                   "to_host": self.OLD, "socks_port": 1099, "http_port": 8099,
                   "selection_source": "retune", "promote_role": False}
        op = self.pool.begin_operation(
            "apply", "auto", desired, "retune:exact", to_uid=row["uid"],
            before_checksum=apply_mod.file_checksum(self.live))
        self.pool.transition_operation(op["id"], "probing")
        stage = apply_mod.stage_candidate(self.cfg, row, probe)[0]
        self.pool.transition_operation(op["id"], "staged",
                                       after_checksum=apply_mod.file_checksum(stage))
        os.replace(stage, self.live)  # kill-point: replace успел, phase=staged
        with self.system_ok() as m:
            m["restart_singbox"].return_value = True
            m["wait_tun0"].return_value = True
            m["verify_egress"].return_value = dict(self.ok_verify, egress_ip=self.OLD)
            m["antiloop_replace"].return_value = "ok"
            m["patch_boot_script"].return_value = False
            result = apply_mod.apply_candidate(
                self.cfg, row, probe, log=lambda *_: None, pool=self.pool,
                requested_by="auto", idempotency_key="retune:exact",
                selection_source="retune")
        self.assertTrue(result["recovered"])
        self.assertEqual(self.pool.get_operation(operation_id=op["id"])["phase"], "verifying")
        self.pool.log_event("retune", actor="auto", result="ok")
        apply_mod.commit_operation(self.pool, result)
        self.assertEqual(self.pool.get_operation(operation_id=op["id"])["phase"], "committed")

    def test_production_retry_after_live_mutation_reuses_intent_operation(self):
        row = dict(self.row, host=self.OLD, ip=self.OLD)
        probe = dict(self.probe, socks_port=1199, http_port=8199)
        desired = {"kind": "apply", "uid": row["uid"], "from_host": self.OLD,
                   "to_host": self.OLD, "socks_port": 1199, "http_port": 8199,
                   "selection_source": "retune", "promote_role": False}
        key = apply_mod._default_apply_key(self.pool, "apply", desired)
        op = self.pool.begin_operation(
            "apply", "auto", desired, key, to_uid=row["uid"],
            before_checksum=apply_mod.file_checksum(self.live))
        self.pool.transition_operation(op["id"], "probing")
        stage = apply_mod.stage_candidate(self.cfg, row, probe)[0]
        self.pool.transition_operation(op["id"], "staged",
                                       after_checksum=apply_mod.file_checksum(stage))
        os.replace(stage, self.live)
        with self.system_ok() as m:
            m["restart_singbox"].return_value = True
            m["wait_tun0"].return_value = True
            m["verify_egress"].return_value = dict(self.ok_verify, egress_ip=self.OLD)
            m["antiloop_replace"].return_value = "ok"
            m["patch_boot_script"].return_value = False
            result = apply_mod.apply_candidate(
                self.cfg, row, probe, log=lambda *_: None, pool=self.pool,
                requested_by="auto", selection_source="retune")
        self.assertEqual(result["operation_id"], op["id"])
        self.assertEqual(self.pool.conn.execute("SELECT COUNT(*) FROM operation").fetchone()[0], 1)
        self.assertEqual(self.pool.get_operation(operation_id=op["id"])["phase"], "verifying")

    def test_production_retry_after_committed_does_not_restart_again(self):
        with self.system_ok() as m:
            m["singbox_check"].return_value = (0, "")
            m["restart_singbox"].return_value = True
            m["wait_tun0"].return_value = True
            m["verify_egress"].return_value = self.ok_verify
            m["antiloop_replace"].return_value = "ok"
            m["patch_boot_script"].return_value = False
            first = apply_mod.apply_candidate(
                self.cfg, self.row, self.probe, log=lambda *_: None,
                pool=self.pool, requested_by="auto", selection_source="rotate")
            apply_mod.commit_operation(self.pool, first)
            second = apply_mod.apply_candidate(
                self.cfg, self.row, self.probe, log=lambda *_: None,
                pool=self.pool, requested_by="auto", selection_source="rotate")
        self.assertEqual(second["operation_id"], first["operation_id"])
        self.assertEqual(self.pool.conn.execute("SELECT COUNT(*) FROM operation").fetchone()[0], 1)
        self.assertEqual(m["restart_singbox"].call_count, 1)

    def test_late_a_b_a_is_new_intent_not_retry_of_old_a(self):
        row_a = self.row
        row_b = dict(self.row, uid="proxy6:b", host="3.3.3.3", ip="3.3.3.3")
        with self.system_ok() as m:
            m["singbox_check"].return_value = (0, "")
            m["restart_singbox"].return_value = True
            m["wait_tun0"].return_value = True
            m["verify_egress"].side_effect = [
                self.ok_verify,
                dict(self.ok_verify, egress_ip="3.3.3.3"),
                self.ok_verify,
            ]
            m["antiloop_replace"].return_value = "ok"
            m["patch_boot_script"].return_value = False
            first_a = apply_mod.apply_candidate(
                self.cfg, row_a, self.probe, log=lambda *_: None,
                pool=self.pool, requested_by="user", selection_source="manual")
            apply_mod.commit_operation(self.pool, first_a)
            middle_b = apply_mod.apply_candidate(
                self.cfg, row_b, self.probe, log=lambda *_: None,
                pool=self.pool, requested_by="user", selection_source="manual")
            apply_mod.commit_operation(self.pool, middle_b)
            late_a = apply_mod.apply_candidate(
                self.cfg, row_a, self.probe, log=lambda *_: None,
                pool=self.pool, requested_by="user", selection_source="manual")
            apply_mod.commit_operation(self.pool, late_a)
        self.assertNotEqual(late_a["operation_id"], first_a["operation_id"])
        self.assertEqual(apply_mod.current_upstream(apply_mod.load_json(self.live)), self.NEW)
        self.assertEqual(self.pool.conn.execute("SELECT COUNT(*) FROM operation").fetchone()[0], 3)
        self.assertEqual(m["restart_singbox"].call_count, 3)

    def test_retry_after_a_b_late_a_continues_latest_nonce_operation(self):
        row_a = self.row
        row_b = dict(self.row, uid="proxy6:b2", host="3.3.3.3", ip="3.3.3.3")
        with self.system_ok() as m:
            m["singbox_check"].return_value = (0, "")
            m["restart_singbox"].return_value = True
            m["wait_tun0"].return_value = True
            m["verify_egress"].side_effect = [
                self.ok_verify, dict(self.ok_verify, egress_ip="3.3.3.3"),
                self.ok_verify, self.ok_verify,
            ]
            m["antiloop_replace"].return_value = "ok"
            m["patch_boot_script"].return_value = False
            old_a = apply_mod.apply_candidate(
                self.cfg, row_a, self.probe, log=lambda *_: None,
                pool=self.pool, requested_by="user", selection_source="manual")
            apply_mod.commit_operation(self.pool, old_a)
            middle_b = apply_mod.apply_candidate(
                self.cfg, row_b, self.probe, log=lambda *_: None,
                pool=self.pool, requested_by="user", selection_source="manual")
            apply_mod.commit_operation(self.pool, middle_b)
            late_a = apply_mod.apply_candidate(
                self.cfg, row_a, self.probe, log=lambda *_: None,
                pool=self.pool, requested_by="user", selection_source="manual")
            # caller погиб до commit: late_a остаётся verifying
            retry = apply_mod.apply_candidate(
                self.cfg, row_a, self.probe, log=lambda *_: None,
                pool=self.pool, requested_by="user", selection_source="manual")
        self.assertEqual(retry["operation_id"], late_a["operation_id"])
        self.assertNotEqual(retry["operation_id"], old_a["operation_id"])
        self.assertEqual(self.pool.get_operation(operation_id=late_a["operation_id"])["phase"],
                         "verifying")
        self.assertEqual(len(self.pool.unfinished_operations()), 1)
        self.assertEqual(m["restart_singbox"].call_count, 3)

    def test_failed_verify_restores_before_and_marks_rolled_back(self):
        bad = {"ok": False, "egress_ip": None, "exit_cc": None,
               "tg_code": "000", "why": "no egress"}
        old_ok = dict(self.ok_verify, egress_ip=self.OLD)
        with self.system_ok() as m:
            m["singbox_check"].return_value = (0, "")
            m["restart_singbox"].return_value = True
            m["wait_tun0"].return_value = True
            m["verify_egress"].side_effect = [bad, old_ok]
            m["antiloop_replace"].return_value = "ok"
            m["patch_boot_script"].return_value = False
            with self.assertRaises(apply_mod.ApplyError):
                apply_mod.apply_candidate(
                    self.cfg, self.row, self.probe, log=lambda *_: None,
                    pool=self.pool, requested_by="test", idempotency_key="apply:rollback")
        op = self.pool.get_operation(operation_id=self.operations()[0]["id"])
        self.assertEqual(op["phase"], "rolled_back")
        self.assertEqual(apply_mod.current_upstream(apply_mod.load_json(self.live)), self.OLD)
        self.assertIn("no egress", op["error"])

    def test_explicit_rollback_has_own_committed_saga(self):
        os.makedirs(self.ring)
        backup = os.path.join(self.ring, "20260822-120000.json")
        self.write(backup, config_for(self.NEW))
        with self.system_ok() as m:
            m["singbox_check"].return_value = (0, "")
            m["restart_singbox"].return_value = True
            m["wait_tun0"].return_value = True
            m["verify_egress"].return_value = self.ok_verify
            m["antiloop_replace"].return_value = "ok"
            m["patch_boot_script"].return_value = False
            result = apply_mod.rollback_from_ring(
                self.cfg, backup_path=backup, log=lambda *_: None,
                pool=self.pool, requested_by="test", idempotency_key="rollback:success")
            apply_mod.commit_operation(self.pool, result)
        op = self.pool.get_operation(operation_id=result["operation_id"])
        self.assertEqual(op["phase"], "committed")
        self.assertEqual(op["kind"], "rollback")
        self.assertEqual(apply_mod.current_upstream(apply_mod.load_json(self.live)), self.NEW)


class TestApplyRecovery(unittest.TestCase):
    OLD = "3.3.3.3"
    NEW = "4.4.4.4"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.live = os.path.join(self.tmp.name, "config.json")
        self.before_file = os.path.join(self.tmp.name, "before.json")
        self.after_file = os.path.join(self.tmp.name, "after.json")
        self.ring = os.path.join(self.tmp.name, "ring")
        os.makedirs(self.ring)
        self.backup = os.path.join(self.ring, "20260822-130000.json")
        self.write(self.before_file, config_for(self.OLD))
        self.write(self.after_file, config_for(self.NEW))
        shutil.copyfile(self.before_file, self.backup)
        shutil.copyfile(self.before_file, self.live)
        self.pool = pool_mod.Pool(os.path.join(self.tmp.name, "state.db"), server="test")
        self.cfg = {"singbox_config": self.live, "ring": self.ring,
                    "boot_script": os.path.join(self.tmp.name, "missing.sh"),
                    "gw": None, "wan": None, "lock": os.path.join(self.tmp.name, "lock")}
        self.before_sum = apply_mod.file_checksum(self.before_file)
        self.after_sum = apply_mod.file_checksum(self.after_file)
        self.ok = {"ok": True, "egress_ip": self.NEW, "exit_cc": "de",
                   "tg_code": "200", "why": ""}

    def tearDown(self):
        self.pool.close()
        self.tmp.cleanup()

    @staticmethod
    def write(path, value):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(value, f, sort_keys=True)

    def seed(self, phase):
        op = self.pool.begin_operation(
            "apply", "test", {"kind": "apply", "uid": "proxy6:new",
                               "from_host": self.OLD, "to_host": self.NEW},
            "recover:%s" % phase, to_uid="proxy6:new",
            before_checksum=self.before_sum)
        if phase == "planned":
            return op
        self.pool.transition_operation(op["id"], "probing")
        if phase == "probing":
            return self.pool.get_operation(operation_id=op["id"])
        self.pool.transition_operation(op["id"], "staged", after_checksum=self.after_sum)
        if phase == "staged":
            return self.pool.get_operation(operation_id=op["id"])
        self.pool.transition_operation(op["id"], "applied")
        if phase == "applied":
            return self.pool.get_operation(operation_id=op["id"])
        self.pool.transition_operation(op["id"], "verifying")
        return self.pool.get_operation(operation_id=op["id"])

    def seed_rollback(self, phase, suffix):
        op = self.pool.begin_operation(
            "rollback", "test", {"kind": "rollback", "from_host": self.OLD,
                                   "to_host": self.NEW, "backup": self.after_file,
                                   "selection_source": "manual"},
            "recover:rollback:%s:%s" % (phase, suffix),
            before_checksum=self.before_sum)
        if phase == "planned":
            return op
        if phase == "probing":
            self.pool.transition_operation(op["id"], "probing")
            return self.pool.get_operation(operation_id=op["id"])
        self.pool.transition_operation(op["id"], "staged", after_checksum=self.after_sum)
        if phase == "staged":
            return self.pool.get_operation(operation_id=op["id"])
        self.pool.transition_operation(op["id"], "applied")
        if phase == "applied":
            return self.pool.get_operation(operation_id=op["id"])
        self.pool.transition_operation(op["id"], "verifying")
        return self.pool.get_operation(operation_id=op["id"])

    def recovery_mocks(self, verify=None):
        return mock.patch.multiple(
            apply_mod, restart_singbox=mock.DEFAULT, wait_tun0=mock.DEFAULT,
            verify_egress=mock.DEFAULT, antiloop_replace=mock.DEFAULT,
            patch_boot_script=mock.DEFAULT)

    def test_kill_before_live_mutation_is_terminalized_without_write(self):
        original = apply_mod.file_checksum(self.live)
        for phase in ("planned", "probing", "staged"):
            op = self.seed(phase)
            result = apply_mod.recover_operation(self.cfg, self.pool, op, log=lambda *_: None)
            self.assertIn(result["action"], ("no-live-change", "failed"))
            self.assertEqual(apply_mod.file_checksum(self.live), original)

    def test_explicit_rollback_kill_points_converge_by_actual_checksum(self):
        """Reboot/kill at every rollback phase leaves either exact before or target."""
        for phase in ("planned", "probing", "staged"):
            with self.subTest(phase=phase, live="before"):
                shutil.copyfile(self.before_file, self.live)
                op = self.seed_rollback(phase, "before")
                result = apply_mod.recover_operation(
                    self.cfg, self.pool, op, log=lambda *_: None,
                    finalize_apply=lambda *_: None)
                self.assertIn(result["action"], ("no-live-change", "failed"))
                self.assertEqual(apply_mod.file_checksum(self.live), self.before_sum)

        for phase in ("staged", "applied", "verifying"):
            with self.subTest(phase=phase, live="target"):
                shutil.copyfile(self.after_file, self.live)
                op = self.seed_rollback(phase, "target")
                with self.recovery_mocks() as m:
                    m["restart_singbox"].return_value = True
                    m["wait_tun0"].return_value = True
                    m["verify_egress"].return_value = self.ok
                    m["antiloop_replace"].return_value = "ok"
                    m["patch_boot_script"].return_value = False
                    result = apply_mod.recover_operation(
                        self.cfg, self.pool, op, log=lambda *_: None,
                        finalize_apply=lambda *_: None)
                self.assertEqual(result["action"], "committed")
                self.assertEqual(apply_mod.file_checksum(self.live), self.after_sum)
                self.assertEqual(
                    self.pool.get_operation(operation_id=op["id"])["phase"], "committed")

    def test_kill_after_replace_from_staged_is_committed(self):
        op = self.seed("staged")
        shutil.copyfile(self.after_file, self.live)
        with self.recovery_mocks() as m:
            m["restart_singbox"].return_value = True
            m["wait_tun0"].return_value = True
            m["verify_egress"].return_value = self.ok
            m["antiloop_replace"].return_value = "ok"
            m["patch_boot_script"].return_value = False
            result = apply_mod.recover_operation(self.cfg, self.pool, op, log=lambda *_: None)
        # прямой recovery без finalize оставляет caller-state pending
        self.assertEqual(result["action"], "post-state-pending")
        apply_mod.commit_operation(self.pool, {"operation_id": op["id"]})
        self.assertEqual(self.pool.get_operation(operation_id=op["id"])["phase"], "committed")

    def test_applied_with_before_means_rollback_already_won(self):
        op = self.seed("applied")
        old_ok = dict(self.ok, egress_ip=self.OLD)
        with self.recovery_mocks() as m:
            m["restart_singbox"].return_value = True
            m["wait_tun0"].return_value = True
            m["verify_egress"].return_value = old_ok
            m["antiloop_replace"].return_value = "ok"
            m["patch_boot_script"].return_value = False
            result = apply_mod.recover_operation(self.cfg, self.pool, op, log=lambda *_: None)
        self.assertEqual(result["action"], "rolled_back")
        self.assertEqual(apply_mod.file_checksum(self.live), self.before_sum)
        m["restart_singbox"].assert_called_once()
        m["wait_tun0"].assert_called_once()

    def test_verify_failure_restores_exact_before_checksum(self):
        op = self.seed("verifying")
        shutil.copyfile(self.after_file, self.live)
        bad = {"ok": False, "egress_ip": None, "exit_cc": None,
               "tg_code": "000", "why": "dead"}
        old_ok = dict(self.ok, egress_ip=self.OLD)
        with self.recovery_mocks() as m:
            m["restart_singbox"].return_value = True
            m["wait_tun0"].return_value = True
            m["verify_egress"].side_effect = [bad, bad, old_ok]
            m["antiloop_replace"].return_value = "ok"
            m["patch_boot_script"].return_value = False
            result = apply_mod.recover_operation(self.cfg, self.pool, op, log=lambda *_: None)
        self.assertEqual(result["action"], "rolled_back")
        self.assertEqual(apply_mod.file_checksum(self.live), self.before_sum)
        self.assertEqual(self.pool.get_operation(operation_id=op["id"])["phase"], "rolled_back")

    def test_unknown_third_live_config_is_never_overwritten(self):
        op = self.seed("staged")
        third = config_for("9.9.9.9")
        self.write(self.live, third)
        checksum = apply_mod.file_checksum(self.live)
        result = apply_mod.recover_operation(self.cfg, self.pool, op, log=lambda *_: None)
        self.assertEqual(result["action"], "superseded")
        self.assertEqual(apply_mod.file_checksum(self.live), checksum)
        self.assertEqual(self.pool.get_operation(operation_id=op["id"])["phase"], "failed")

    def test_recover_all_processes_oldest_first(self):
        one = self.seed("planned")
        two = self.seed("probing")
        results = apply_mod.recover_unfinished_operations(self.cfg, self.pool, log=lambda *_: None)
        self.assertEqual([r["operation_id"] for r in results], [one["id"], two["id"]])
        self.assertEqual(self.pool.unfinished_operations(), [])

    def test_manual_post_state_is_recovered_before_commit(self):
        op = self.pool.begin_operation(
            "apply", "user", {"kind": "apply", "uid": "proxy6:new",
                               "from_host": self.OLD, "to_host": self.NEW,
                               "selection_source": "manual", "promote_role": False},
            "recover:manual", to_uid="proxy6:new", before_checksum=self.before_sum)
        self.pool.transition_operation(op["id"], "probing")
        self.pool.transition_operation(op["id"], "staged", after_checksum=self.after_sum)
        self.pool.transition_operation(op["id"], "applied")
        self.pool.transition_operation(op["id"], "verifying")
        states_mod.set_manual_selection(self.pool, "live:old", self.OLD)
        shutil.copyfile(self.after_file, self.live)
        with self.recovery_mocks() as m:
            m["restart_singbox"].return_value = True
            m["wait_tun0"].return_value = True
            m["verify_egress"].return_value = self.ok
            m["antiloop_replace"].return_value = "ok"
            m["patch_boot_script"].return_value = False
            result = apply_mod.recover_operation(
                self.cfg, self.pool, self.pool.get_operation(operation_id=op["id"]),
                log=lambda *_: None,
                finalize_apply=lambda operation, verify: states_mod.recover_apply_post_state(
                    self.cfg, self.pool, operation, verify, log=lambda *_: None))
        self.assertEqual(result["action"], "committed")
        self.assertEqual(states_mod.selection_state(self.pool)["manual_host"], self.NEW)

    def test_setup_recovery_post_state_matches_normal_auto_transition(self):
        for source in ("setup", "recovery"):
            states_mod.set_manual_selection(self.pool, "live:old", self.OLD)
            operation = {"id": "op-" + source, "requested_by": "auto", "to_uid": None,
                         "desired_state": {"uid": None, "to_host": self.NEW,
                                           "selection_source": source,
                                           "promote_role": False}}
            states_mod.recover_apply_post_state(
                self.cfg, self.pool, operation, self.ok, log=lambda *_: None)
            selection = states_mod.selection_state(self.pool, self.cfg, self.NEW)
            self.assertEqual(selection["mode"], states_mod.SELECTION_AUTO, source)
            self.assertIsNone(selection["manual_host"], source)

    def test_transient_db_error_inside_recovery_keeps_operation_unfinished(self):
        op = self.seed("staged")
        shutil.copyfile(self.after_file, self.live)
        original = self.pool.transition_operation
        failed = {"done": False}

        def transient(operation_id, phase, **kwargs):
            if phase == "applied" and not failed["done"]:
                failed["done"] = True
                raise __import__("sqlite3").OperationalError("busy once")
            return original(operation_id, phase, **kwargs)

        with mock.patch.object(self.pool, "transition_operation", side_effect=transient):
            result = apply_mod.recover_unfinished_operations(
                self.cfg, self.pool, log=lambda *_: None,
                finalize_apply=lambda *_: None)
        self.assertEqual(result[0]["action"], "deferred")
        self.assertEqual(self.pool.get_operation(operation_id=op["id"])["phase"], "staged")
        self.assertEqual(len(self.pool.unfinished_operations()), 1)

    def test_failed_explicit_rollback_recovery_compensates_to_before(self):
        op = self.pool.begin_operation(
            "rollback", "user", {"kind": "rollback", "from_host": self.OLD,
                                  "to_host": self.NEW, "backup": self.after_file,
                                  "selection_source": "manual"},
            "recover:rollback-fail", before_checksum=self.before_sum)
        self.pool.transition_operation(op["id"], "staged", after_checksum=self.after_sum)
        self.pool.transition_operation(op["id"], "applied")
        shutil.copyfile(self.after_file, self.live)
        bad = {"ok": False, "egress_ip": None, "exit_cc": None,
               "tg_code": "000", "why": "still dead"}
        with self.recovery_mocks() as m:
            m["restart_singbox"].return_value = False
            m["wait_tun0"].return_value = False
            m["verify_egress"].return_value = bad
            m["antiloop_replace"].return_value = "ok"
            m["patch_boot_script"].return_value = False
            result = apply_mod.recover_operation(
                self.cfg, self.pool, self.pool.get_operation(operation_id=op["id"]),
                log=lambda *_: None, finalize_apply=lambda *_: None)
        self.assertEqual(result["action"], "deferred")
        self.assertEqual(apply_mod.file_checksum(self.live), self.before_sum)
        self.assertEqual(self.pool.get_operation(operation_id=op["id"])["phase"], "verifying")
        self.assertEqual(len(self.pool.unfinished_operations()), 1)


if __name__ == "__main__":
    unittest.main()
