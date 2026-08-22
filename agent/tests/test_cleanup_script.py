# -*- coding: utf-8 -*-
"""Регрессии статистики /usr/local/bin/server_cleanup.sh.

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


def collect(path, logs, tmpb, before, after, vacuum):
    proc = subprocess.run(
        [sys.executable, "-", path, str(logs), str(tmpb), before, after, vacuum],
        input=embedded_stats_code(), text=True, encoding="utf-8",
        capture_output=True, timeout=10)
    if proc.returncode:
        raise AssertionError(proc.stderr)
    with open(path, encoding="utf-8") as f:
        return json.load(f)


class TestCleanupCollector(unittest.TestCase):
    def test_vacuum_result_wins_when_total_disk_usage_is_unchanged(self):
        """Регрессия узла: новый active-файл заменил удалённый 8 MiB."""
        with tempfile.TemporaryDirectory() as d:
            out = collect(os.path.join(d, "stat.json"), 100, 20,
                          "Archived journals take up 8M.",
                          "Archived journals take up 8M.",
                          "Vacuuming done, freed 8.0M of archived journals from /var/log/journal/x.")
            self.assertEqual(out["freed_24h"], 8 * 1024 * 1024 + 120)
            self.assertEqual(out["runs_24h"], 1)
            self.assertEqual(out["runs"][0]["journal"], 8 * 1024 * 1024)

    def test_sums_multiple_journal_directories_and_previous_run(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "stat.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"runs": [[time.time() - 60, 7]]}, f)
            out = collect(path, 0, 0, "8M", "8M",
                          "Vacuuming done, freed 8M from /run.\n"
                          "Vacuuming done, freed 512K from /var.")
            self.assertEqual(out["freed_24h"], 7 + 8 * 1024 * 1024 + 512 * 1024)
            self.assertEqual(out["runs_24h"], 2)
            self.assertTrue(all(isinstance(r, dict) for r in out["runs"]))

    def test_disk_usage_delta_is_fallback_for_old_journalctl(self):
        with tempfile.TemporaryDirectory() as d:
            out = collect(os.path.join(d, "stat.json"), 0, 0, "16M", "8M", "")
            self.assertEqual(out["freed_24h"], 8 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main(verbosity=2)
