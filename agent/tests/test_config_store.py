# -*- coding: utf-8 -*-
"""Атомарная запись config.json из панели и агента."""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

import _ctx  # noqa: F401
import config_store


class TestConfigStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "config.json")
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump({"countries": {"blacklist": ["tr"], "strategy": "balanced"},
                       "money": {"max_buys_per_day": 2}}, f)
        self.cfg = {"_source": self.path, "countries": {"strategy": "balanced"},
                    "_runtime_only": True}

    def tearDown(self):
        self.tmp.cleanup()

    def test_strategy_update_preserves_neighbours_and_runtime_fields_stay_memory_only(self):
        config_store.save_country_strategy(self.cfg, "speed")
        with open(self.path, encoding="utf-8") as f:
            saved = json.load(f)
        self.assertEqual(saved["countries"], {"blacklist": ["tr"], "strategy": "speed"})
        self.assertEqual(saved["money"]["max_buys_per_day"], 2)
        self.assertNotIn("_runtime_only", saved)
        self.assertEqual(self.cfg["countries"]["strategy"], "speed")

    def test_refresh_observes_change_from_another_process(self):
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump({"countries": {"strategy": "reputation"}}, f)
        self.assertEqual(config_store.refresh_country_strategy(self.cfg), "reputation")
        self.assertEqual(self.cfg["countries"]["strategy"], "reputation")

    def test_refresh_observes_removed_strategy_and_restores_default_semantics(self):
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump({"countries": {"blacklist": ["tr"]}}, f)
        self.assertIsNone(config_store.refresh_country_strategy(self.cfg))
        self.assertNotIn("strategy", self.cfg["countries"])

    def test_failed_mutator_does_not_damage_original(self):
        with open(self.path, "rb") as f:
            before = f.read()
        with self.assertRaises(RuntimeError):
            config_store.update(self.cfg, lambda data: (_ for _ in ()).throw(RuntimeError("boom")))
        with open(self.path, "rb") as f:
            self.assertEqual(f.read(), before)
        self.assertFalse(any(n.startswith(".redut-config-") for n in os.listdir(self.tmp.name)))

    def test_writer_lock_serializes_separate_processes(self):
        first_flag = os.path.join(self.tmp.name, "first.locked")
        second_flag = os.path.join(self.tmp.name, "second.locked")
        release = os.path.join(self.tmp.name, "release")
        script = (
            "import os,sys,time,config_store; cfg={'_source':sys.argv[1]}; "
            "cm=config_store.writer(cfg); cm.__enter__(); "
            "open(sys.argv[2],'w').close(); "
            "deadline=time.time()+5; "
            "exec(\"while sys.argv[3] != '-' and not os.path.exists(sys.argv[3]) "
            "and time.time() < deadline: time.sleep(.02)\"); cm.__exit__(None,None,None)")
        cwd = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        first = subprocess.Popen(
            [sys.executable, "-c", script, self.path, first_flag, release], cwd=cwd)
        second = None
        try:
            deadline = time.time() + 3
            while not os.path.exists(first_flag) and time.time() < deadline:
                time.sleep(0.02)
            self.assertTrue(os.path.exists(first_flag))
            second = subprocess.Popen(
                [sys.executable, "-c", script, self.path, second_flag, "-"], cwd=cwd)
            time.sleep(0.15)
            self.assertFalse(os.path.exists(second_flag),
                             "другой процесс вошёл в writer до освобождения lock")
            with open(release, "w", encoding="ascii"):
                pass
            self.assertEqual(first.wait(timeout=3), 0)
            self.assertEqual(second.wait(timeout=3), 0)
            self.assertTrue(os.path.exists(second_flag))
        finally:
            for proc in (first, second):
                if proc is not None and proc.poll() is None:
                    proc.kill()
                    proc.wait()

    def test_writer_lock_is_outside_read_only_config_directory(self):
        lock_path = config_store._runtime_lock_path(self.path)
        self.assertNotEqual(os.path.dirname(lock_path), os.path.dirname(self.path))
        self.assertTrue(os.path.isdir(os.path.dirname(lock_path)))


if __name__ == "__main__":
    unittest.main()
