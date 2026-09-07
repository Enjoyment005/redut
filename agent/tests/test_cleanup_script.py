# -*- coding: utf-8 -*-
"""Регрессии bounded-статистики /usr/local/bin/server_cleanup.sh.

Выполняем только встроенный Python-блок шаблона с временным stat-файлом:
системные журналы и остальные файлы тест не трогает.
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

from _ctx import PANEL_DIR


TEMPLATE = os.path.join(os.path.dirname(PANEL_DIR), "install", "templates", "server_cleanup.sh")


def embedded_stats_code():
    with open(TEMPLATE, encoding="utf-8") as f:
        source = f.read()
    marker = "<<'PY'\n"
    start = source.index(marker) + len(marker)
    end = source.index("\nPY\n", start)
    return source[start:end]


def collect(path, freed):
    proc = subprocess.run(
        [sys.executable, "-", path, str(freed)],
        input=embedded_stats_code(), text=True, encoding="utf-8",
        capture_output=True, timeout=10)
    if proc.returncode:
        raise AssertionError(proc.stderr)
    with open(path, encoding="utf-8") as f:
        return json.load(f)


class TestCleanupCollector(unittest.TestCase):
    def test_records_only_redut_owned_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            out = collect(os.path.join(d, "stat.json"), 120)
            self.assertEqual(out["freed_24h"], 120)
            self.assertEqual(out["runs_24h"], 1)
            self.assertEqual(out["runs"][0]["scope"], "redut-owned")
            self.assertEqual(out["scope"], "redut-owned")

    def test_sums_recent_runs_and_drops_old_history(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "stat.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"runs": [
                    {"at": time.time() - 60, "freed": 7, "scope": "redut-owned"},
                    {"at": time.time() - 90000, "freed": 999},
                ]}, f)
            out = collect(path, 11)
            self.assertEqual(out["freed_24h"], 18)
            self.assertEqual(out["runs_24h"], 2)
            self.assertTrue(all(isinstance(r, dict) for r in out["runs"]))

    def test_invalid_previous_stat_is_replaced_safely(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "stat.json")
            with open(path, "w", encoding="utf-8") as target:
                target.write("not-json")
            out = collect(path, 5)
            self.assertEqual(out["freed_24h"], 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
