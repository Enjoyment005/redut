# -*- coding: utf-8 -*-
import os
import sqlite3
import tempfile
import threading
import unittest

import _ctx  # noqa: F401
import pool


class TestPoolDBReliability(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "state.db")

    def tearDown(self):
        self.tmp.cleanup()

    def test_wal_full_busy_timeout_and_foreign_keys(self):
        p = pool.Pool(self.path)
        try:
            self.assertEqual(p.conn.execute("PRAGMA journal_mode").fetchone()[0].lower(), "wal")
            self.assertEqual(p.conn.execute("PRAGMA synchronous").fetchone()[0], 2)
            self.assertEqual(p.conn.execute("PRAGMA busy_timeout").fetchone()[0], 5000)
            self.assertEqual(p.conn.execute("PRAGMA foreign_keys").fetchone()[0], 1)
        finally:
            p.close()

    def test_transaction_rolls_back_callback_failure(self):
        p = pool.Pool(self.path)
        try:
            p.set_setting("counter", 0)
            def broken(conn):
                conn.execute("UPDATE setting SET value='1' WHERE key='counter'")
                raise RuntimeError("boom")
            with self.assertRaisesRegex(RuntimeError, "boom"):
                p.run_transaction(broken)
            self.assertEqual(p.get_setting("counter"), "0")
        finally:
            p.close()

    def test_parallel_connections_do_not_lose_updates(self):
        seed = pool.Pool(self.path)
        seed.set_setting("counter", 0)
        seed.close()
        errors = []
        def worker():
            p = pool.Pool(self.path)
            try:
                for _ in range(40):
                    p.run_transaction(lambda conn: conn.execute(
                        "UPDATE setting SET value=CAST(value AS INTEGER)+1 WHERE key='counter'"))
            except Exception as e:
                errors.append(e)
            finally:
                p.close()
        threads = [threading.Thread(target=worker) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
        self.assertFalse(errors)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        check = pool.Pool(self.path)
        try:
            self.assertEqual(check.get_setting("counter"), "240")
        finally:
            check.close()

    def test_error_classification(self):
        busy = sqlite3.OperationalError("database is locked")
        self.assertIsInstance(pool.classify_db_error(busy), pool.PoolBusy)
        corrupt = sqlite3.DatabaseError("database disk image is malformed")
        self.assertIsInstance(pool.classify_db_error(corrupt), pool.PoolCorrupt)
        self.assertIsInstance(pool.classify_db_error(
            sqlite3.DatabaseError("file is not a database")), pool.PoolCorrupt)
        for text in ("database or disk is full", "attempt to write a readonly database",
                     "disk I/O error"):
            self.assertIsInstance(pool.classify_db_error(sqlite3.OperationalError(text)),
                                  pool.PoolStorageError)

    def test_nested_transaction_is_rejected_without_rolling_back_owner(self):
        p = pool.Pool(self.path)
        try:
            p.conn.execute("BEGIN")
            p.conn.execute("INSERT OR REPLACE INTO setting(key,value) VALUES('outer','yes')")
            with self.assertRaises(pool.PoolDBError):
                p.run_transaction(lambda conn: None)
            self.assertTrue(p.conn.in_transaction)
            p.conn.commit()
            self.assertEqual(p.get_setting("outer"), "yes")
        finally:
            p.close()

    def test_keyboard_interrupt_rolls_back_and_connection_remains_usable(self):
        p = pool.Pool(self.path)
        p.set_setting("counter", 0)
        def interrupted(conn):
            conn.execute("UPDATE setting SET value='1' WHERE key='counter'")
            raise KeyboardInterrupt
        try:
            with self.assertRaises(KeyboardInterrupt):
                p.run_transaction(interrupted)
            self.assertFalse(p.conn.in_transaction)
            self.assertEqual(p.get_setting("counter"), "0")
        finally:
            p.close()

    def test_corrupt_init_is_classified_and_releases_file(self):
        with open(self.path, "wb") as f:
            f.write(b"not a sqlite database")
        with self.assertRaises(pool.PoolCorrupt):
            pool.Pool(self.path)
        os.replace(self.path, self.path + ".moved")
        self.assertTrue(os.path.isfile(self.path + ".moved"))

    def test_cannot_open_is_storage_error(self):
        with self.assertRaises(pool.PoolStorageError):
            pool.Pool(self.tmp.name)
        self.assertIsInstance(pool.classify_db_error(
            sqlite3.OperationalError("unable to open database file")),
            pool.PoolStorageError)

    def test_roles_snapshot_contains_committed_wal_rows(self):
        first = pool.Pool(self.path)
        try:
            uid = first.upsert_proxy({
                "provider": "proxy6", "ext_id": "x", "ip": "1.1.1.1",
                "host": "1.1.1.1", "port_http": 1, "port_socks5": 2,
                "user": "u", "password": "p", "country": "de", "ip_version": 4,
                "kind": "dedicated", "date_end": None, "descr": ""})
            first.conn.execute("UPDATE proxy SET role='chrome' WHERE uid=?", (uid,))
            first.conn.execute("DELETE FROM setting WHERE key='roles_v2'")
            first.conn.commit()
            second = pool.Pool(self.path)
            second.close()
            snap = sqlite3.connect(self.path + ".pre-roles-v2")
            try:
                role = snap.execute("SELECT role FROM proxy WHERE uid=?", (uid,)).fetchone()[0]
                self.assertEqual(role, "chrome")
            finally:
                snap.close()
        finally:
            first.close()

    def test_invalid_existing_roles_snapshot_is_replaced(self):
        first = pool.Pool(self.path)
        try:
            uid = first.upsert_proxy({
                "provider": "proxy6", "ext_id": "bad-snap", "ip": "2.2.2.2",
                "host": "2.2.2.2", "port_http": 1, "port_socks5": 2,
                "user": "u", "password": "p", "country": "de", "ip_version": 4,
                "kind": "dedicated", "date_end": None, "descr": ""})
            first.conn.execute("UPDATE proxy SET role='chrome' WHERE uid=?", (uid,))
            first.conn.execute("DELETE FROM setting WHERE key='roles_v2'")
            first.conn.commit()
            open(self.path + ".pre-roles-v2", "wb").close()
            second = pool.Pool(self.path)
            second.close()
            snap = sqlite3.connect(self.path + ".pre-roles-v2")
            try:
                self.assertEqual(snap.execute(
                    "SELECT role FROM proxy WHERE uid=?", (uid,)).fetchone()[0], "chrome")
            finally:
                snap.close()
        finally:
            first.close()


if __name__ == "__main__":
    unittest.main()
