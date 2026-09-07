# -*- coding: utf-8 -*-
"""Атомарная запись config.json из панели и агента."""
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import _ctx  # noqa: F401
import config_store
from webpanel import server


class TestConfigStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "config.json")
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump({"countries": {"blacklist": ["tr"], "strategy": "balanced"},
                       "money": {"max_buys_per_day": 2},
                       "update": {"auto": True, "window": "04:00-06:00"}}, f)
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

    def test_update_auto_preserves_concurrent_strategy_and_runtime_fields(self):
        config_store.save_country_strategy(self.cfg, "speed")
        config_store.save_update_auto(self.cfg, False)
        with open(self.path, encoding="utf-8") as f:
            saved = json.load(f)
        self.assertEqual(saved["countries"]["strategy"], "speed")
        self.assertFalse(saved["update"]["auto"])
        self.assertEqual(saved["money"]["max_buys_per_day"], 2)
        self.assertNotIn("_runtime_only", saved)
        self.assertFalse(self.cfg["update"]["auto"])

    def _app(self):
        app = server.App.__new__(server.App)
        app.cfg = self.cfg
        return app

    def test_real_app_toggle_waits_for_agent_writer_then_preserves_both_changes(self):
        locked = os.path.join(self.tmp.name, "agent-read")
        release = os.path.join(self.tmp.name, "release-agent")
        script = (
            "import os,sys,time,config_store; cfg={'_source':sys.argv[1]}; "
            "original=config_store.read; "
            "exec(\"def paused(cfg):\\n data=original(cfg)\\n open(sys.argv[2],'w').close()\\n"
            " while not os.path.exists(sys.argv[3]): time.sleep(.01)\\n return data\"); "
            "config_store.read=paused; config_store.save_country_strategy(cfg,'speed')")
        cwd = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        proc = subprocess.Popen([sys.executable, "-c", script, self.path, locked, release], cwd=cwd)
        toggle = None
        try:
            deadline = time.time() + 3
            while not os.path.exists(locked) and time.time() < deadline:
                time.sleep(0.02)
            self.assertTrue(os.path.exists(locked))
            toggle = threading.Thread(target=self._app().save_update_auto, args=(False,))
            toggle.start()
            time.sleep(0.15)
            self.assertTrue(toggle.is_alive(), "App bypassed the common interprocess writer")
            open(release, "w").close()
            self.assertEqual(proc.wait(timeout=3), 0)
            toggle.join(timeout=3)
            self.assertFalse(toggle.is_alive())
            with open(self.path, encoding="utf-8") as handle:
                final = json.load(handle)
            self.assertEqual(final["countries"]["strategy"], "speed")
            self.assertFalse(final["update"]["auto"])
            self.assertEqual(final["update"]["window"], "04:00-06:00")
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            if toggle is not None:
                toggle.join(timeout=1)

    def test_agent_writer_waits_for_real_app_toggle_then_preserves_both_changes(self):
        read_done = threading.Event()
        release = threading.Event()
        original_read = config_store.read

        def paused_read(cfg):
            data = original_read(cfg)
            read_done.set()
            self.assertTrue(release.wait(3))
            return data

        app = self._app()
        toggle = threading.Thread(target=app.save_update_auto, args=(False,))
        with mock.patch.object(config_store, "read", side_effect=paused_read):
            toggle.start()
            self.assertTrue(read_done.wait(3))
            done = os.path.join(self.tmp.name, "strategy-done")
            script = ("import sys,config_store; cfg={'_source':sys.argv[1]}; "
                      "config_store.save_country_strategy(cfg,'speed'); open(sys.argv[2],'w').close()")
            cwd = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            proc = subprocess.Popen([sys.executable, "-c", script, self.path, done], cwd=cwd)
            try:
                time.sleep(0.15)
                self.assertFalse(os.path.exists(done), "agent writer bypassed App's config lock")
                release.set()
                toggle.join(timeout=3)
                self.assertEqual(proc.wait(timeout=3), 0)
            finally:
                release.set()
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()
        with open(self.path, encoding="utf-8") as handle:
            final = json.load(handle)
        self.assertEqual(final["countries"]["strategy"], "speed")
        self.assertFalse(final["update"]["auto"])

    def test_replace_failure_leaves_exact_old_or_new_document(self):
        with open(self.path, encoding="utf-8") as handle:
            old = json.load(handle)
        with mock.patch.object(config_store.os, "replace", side_effect=OSError("before replace")):
            with self.assertRaises(OSError):
                config_store.save_update_auto(self.cfg, False)
        with open(self.path, encoding="utf-8") as handle:
            self.assertEqual(json.load(handle), old)

        real_replace = os.replace

        def replace_then_fail(src, dst):
            real_replace(src, dst)
            raise OSError("after replace")

        with mock.patch.object(config_store.os, "replace", side_effect=replace_then_fail):
            with self.assertRaises(OSError):
                config_store.save_update_auto(self.cfg, False)
        with open(self.path, encoding="utf-8") as handle:
            new = json.load(handle)
        self.assertFalse(new["update"]["auto"])
        self.assertEqual(new["countries"], old["countries"])

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
