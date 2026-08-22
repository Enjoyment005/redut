# -*- coding: utf-8 -*-
"""P0: журнал operation saga — миграция, идемпотентность, фазы и атомарный audit."""
import os
import tempfile
import threading
import unittest

import _ctx
import pool as pool_mod


class TestOperationSaga(unittest.TestCase):
    def setUp(self):
        fd, self.db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.pool = pool_mod.Pool(self.db, server="test")

    def tearDown(self):
        self.pool.close()
        os.unlink(self.db)

    def begin(self, key="apply:test:1", desired=None):
        return self.pool.begin_operation(
            "apply", "user", desired or {"uid": "proxy6:21", "strategy": "speed"}, key,
            from_uid="proxyline:old", to_uid="proxy6:21", before_checksum="aaa")

    def test_schema_is_migrated_idempotently(self):
        self.pool.conn.execute(
            "INSERT OR REPLACE INTO setting(key,value) VALUES('schema_version','1')")
        self.pool.conn.commit()
        pool_mod.migrate(self.pool.conn, self.db)
        pool_mod.migrate(self.pool.conn, self.db)
        columns = {r[1] for r in self.pool.conn.execute("PRAGMA table_info(operation)")}
        self.assertLessEqual({"id", "kind", "desired_state", "phase", "idempotency_key",
                              "before_checksum", "after_checksum", "error"}, columns)
        self.assertEqual(self.pool.get_setting("schema_version"), pool_mod.SCHEMA_VERSION)

    def test_migration_never_downgrades_future_schema_marker(self):
        self.pool.set_setting("schema_version", "999")
        pool_mod.migrate(self.pool.conn, self.db)
        self.assertEqual(self.pool.get_setting("schema_version"), "999")

    def test_concurrent_exact_retry_is_idempotent(self):
        other = pool_mod.Pool(self.db, server="test")
        barrier = threading.Barrier(2)
        results = []
        errors = []

        def run(p):
            try:
                barrier.wait()
                results.append(p.begin_operation(
                    "apply", "user", {"uid": "proxy6:21"}, "concurrent:key",
                    to_uid="proxy6:21"))
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=run, args=(p,)) for p in (self.pool, other)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
        other.close()
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 2)
        self.assertEqual({r["id"] for r in results}, {results[0]["id"]})
        self.assertEqual(sorted(r["created"] for r in results), [False, True])
        self.assertEqual(self.pool.conn.execute("SELECT COUNT(*) FROM operation").fetchone()[0], 1)

    def test_begin_and_exact_retry_are_idempotent(self):
        first = self.begin()
        second = self.begin()
        self.assertTrue(first["created"])
        self.assertFalse(second["created"])
        self.assertEqual(first["id"], second["id"])
        self.assertEqual(first["desired_state"], {"strategy": "speed", "uid": "proxy6:21"})
        count = self.pool.conn.execute("SELECT COUNT(*) FROM operation").fetchone()[0]
        events = self.pool.conn.execute(
            "SELECT COUNT(*) FROM event WHERE action='operation' AND result='planned'").fetchone()[0]
        self.assertEqual((count, events), (1, 1))

    def test_same_key_for_different_intent_is_rejected(self):
        self.begin()
        with self.assertRaisesRegex(ValueError, "другим намерением"):
            self.begin(desired={"uid": "proxy6:11"})
        self.assertEqual(self.pool.conn.execute("SELECT COUNT(*) FROM operation").fetchone()[0], 1)

    def test_non_json_and_nan_desired_state_are_rejected(self):
        with self.assertRaises(ValueError):
            self.begin(desired={"bad": object()})
        with self.assertRaises(ValueError):
            self.begin(key="apply:test:nan", desired={"score": float("nan")})
        self.assertEqual(self.pool.conn.execute("SELECT COUNT(*) FROM operation").fetchone()[0], 0)

    def test_valid_lifecycle_and_checksums(self):
        op = self.begin()
        for phase in ("probing", "staged", "applied", "verifying"):
            op = self.pool.transition_operation(op["id"], phase)
        op = self.pool.transition_operation(op["id"], "committed", after_checksum="bbb")
        self.assertEqual(op["phase"], "committed")
        self.assertEqual(op["before_checksum"], "aaa")
        self.assertEqual(op["after_checksum"], "bbb")
        self.assertTrue(op["finished_at"])
        self.assertEqual(self.pool.unfinished_operations(), [])

    def test_phase_repeat_is_idempotent_and_terminal_is_immutable(self):
        op = self.begin()
        op = self.pool.transition_operation(op["id"], "probing")
        n = self.pool.conn.execute("SELECT COUNT(*) FROM event WHERE action='operation'").fetchone()[0]
        again = self.pool.transition_operation(op["id"], "probing")
        self.assertEqual(again["phase"], "probing")
        self.assertEqual(self.pool.conn.execute(
            "SELECT COUNT(*) FROM event WHERE action='operation'").fetchone()[0], n)
        self.pool.transition_operation(op["id"], "failed", error="probe timeout")
        with self.assertRaises(ValueError):
            self.pool.transition_operation(op["id"], "probing")

    def test_invalid_jump_and_missing_operation_are_rejected(self):
        op = self.begin()
        with self.assertRaises(ValueError):
            self.pool.transition_operation(op["id"], "committed")
        with self.assertRaises(KeyError):
            self.pool.transition_operation("missing", "failed")
        self.assertEqual(self.pool.get_operation(operation_id=op["id"])["phase"], "planned")

    def test_unfinished_are_oldest_first_and_terminal_excluded(self):
        one = self.begin("apply:test:one")
        two = self.begin("apply:test:two")
        self.pool.transition_operation(one["id"], "failed", error="cancelled")
        pending = self.pool.unfinished_operations(limit="bad")
        self.assertEqual([x["id"] for x in pending], [two["id"]])

    def test_corrupt_desired_state_remains_visible_for_recovery(self):
        op = self.begin()
        self.pool.conn.execute("UPDATE operation SET desired_state='{' WHERE id=?", (op["id"],))
        self.pool.conn.commit()
        got = self.pool.get_operation(operation_id=op["id"])
        self.assertEqual(got["desired_state"], "{")
        self.assertTrue(got["desired_state_invalid"])

    def test_non_standard_nan_in_db_is_marked_invalid(self):
        op = self.begin()
        self.pool.conn.execute("UPDATE operation SET desired_state='NaN' WHERE id=?", (op["id"],))
        self.pool.conn.commit()
        got = self.pool.get_operation(operation_id=op["id"])
        self.assertEqual(got["desired_state"], "NaN")
        self.assertTrue(got["desired_state_invalid"])

    def test_unknown_phase_can_be_repaired_to_failed(self):
        op = self.begin()
        self.pool.conn.execute("UPDATE operation SET phase='garbage' WHERE id=?", (op["id"],))
        self.pool.conn.commit()
        self.assertEqual(self.pool.unfinished_operations()[0]["phase"], "garbage")
        failed = self.pool.transition_operation(op["id"], "failed", error="corrupt phase")
        self.assertEqual(failed["phase"], "failed")
        self.assertEqual(self.pool.unfinished_operations(), [])

    def test_unfinished_same_second_keep_insertion_order(self):
        made = [self.begin("ordered:%02d" % i)["id"] for i in range(20)]
        got = [op["id"] for op in self.pool.unfinished_operations()]
        self.assertEqual(got, made)


if __name__ == "__main__":
    unittest.main()
