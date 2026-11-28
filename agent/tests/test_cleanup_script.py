# -*- coding: utf-8 -*-
"""Регрессии bounded-статистики /usr/local/bin/server_cleanup.sh.

Выполняем сборщик статистики и полный shell-сценарий в отдельных временных
каталогах. Настоящие журналы и временные файлы узла тесты не трогают.
"""
import json
import os
from pathlib import Path
import shlex
import shutil
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


def collect(path, freed, logs=0):
    proc = subprocess.run(
        [sys.executable, "-", path, str(freed), str(logs)],
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

    def test_records_log_bytes_in_total(self):
        with tempfile.TemporaryDirectory() as d:
            out = collect(os.path.join(d, "stat.json"), 120, logs=800)
            self.assertEqual(out["freed_24h"], 920)
            self.assertEqual(out["runs"][-1]["files"], 800)
            self.assertEqual(out["runs"][-1]["tmp"], 120)
            self.assertEqual(out["runs"][-1]["accounting_version"], 2)

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

    def test_keeps_legacy_runs_and_skips_invalid_or_future_measurements(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "stat.json")
            now = time.time()
            with open(path, "w", encoding="utf-8") as target:
                json.dump({"runs": [
                    [now - 10, 15],
                    {"at": now, "freed": float("nan")},
                    {"at": now, "freed": -8},
                    {"at": now + 900, "freed": 900},
                    {"at": now, "freed": "invalid"},
                ]}, target)
            out = collect(path, 5, logs=2)
            self.assertEqual(out["freed_24h"], 22)
            self.assertEqual(out["runs_24h"], 2)
            self.assertNotIn("accounting_version", out["runs"][0])

    def test_wrong_previous_document_type_does_not_stall_collector(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "stat.json")
            for old in ([1], {"runs": 1}, {"runs": "invalid"}):
                with self.subTest(old=old):
                    with open(path, "w", encoding="utf-8") as target:
                        json.dump(old, target)
                    self.assertEqual(collect(path, 5)["freed_24h"], 5)


@unittest.skipUnless(shutil.which("bash"), "bash required")
class TestCleanupOperations(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.state = self.root / "state"
        self.logs = [self.root / "watchdog.log", self.root / "whitelist.log"]
        self.tmp = [self.root / "tmp", self.root / "var-tmp"]
        for path in [self.state] + self.tmp:
            path.mkdir()
        source = Path(TEMPLATE).read_text()
        # Only paths and the fixture owner differ from the installed script.
        source = source.replace("STATE_DIR=/var/lib/vpn-panel", "STATE_DIR=" + shlex.quote(str(self.state)))
        source = source.replace("for root in /tmp /var/tmp; do", "for root in " + shlex.join(map(str, self.tmp)) + "; do")
        source = source.replace("/var/log/singbox-watchdog.log /var/log/ru-whitelist-update.log", shlex.join(map(str, self.logs)))
        source = source.replace("-user root", "-uid " + str(os.getuid()))
        self.script = self.root / "cleanup.sh"
        self.script.write_text(source)

    def run_cleanup(self, fail_command=None):
        env = dict(os.environ)
        if fail_command:
            commands = self.root / "commands"
            commands.mkdir(exist_ok=True)
            command = commands / ("rm" if fail_command == "delete" else fail_command)
            command.write_text("#!/bin/sh\nexit 1\n")
            command.chmod(0o755)
            if fail_command == "delete":
                command = commands / "find"
                command.write_text("#!/bin/sh\nfor arg do\n[ \"$arg\" != -delete ] || exit 1\ndone\nexec "
                                   + shlex.quote(shutil.which("find")) + " \"$@\"\n")
                command.chmod(0o755)
            env["PATH"] = str(commands) + os.pathsep + env["PATH"]
        proc = subprocess.run(["bash", str(self.script)], env=env,
                              capture_output=True, text=True, timeout=10)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        path = self.state / "cleanup-stat.json"
        return json.loads(path.read_text()) if path.exists() else None

    def old_file(self, name, data=b"temporary data\n"):
        path = self.tmp[0] / name
        path.write_bytes(data)
        os.utime(path, (time.time() - 3 * 86400,) * 2)
        return path

    def test_full_script_counts_removed_log_tail_and_successful_tmp_deletion(self):
        data = b"".join(("record %04d\n" % i).encode() for i in range(350))
        self.logs[0].write_bytes(data)
        self.logs[1].write_bytes(b"short log\n")
        owned = self.old_file("redut-old.tmp", b"x" * 4096)
        foreign = self.old_file("foreign.tmp")
        fresh = self.tmp[0] / "redut-fresh.tmp"
        fresh.write_bytes(b"keep")
        out = self.run_cleanup()
        tail = b"".join(data.splitlines(keepends=True)[-200:])
        removed = len(data) - len(tail)
        self.assertEqual(self.logs[0].read_bytes(), tail)
        self.assertFalse(owned.exists())
        self.assertTrue(foreign.exists())
        self.assertTrue(fresh.exists())
        self.assertEqual(out["freed_24h"], 4096 + removed)
        self.assertEqual(out["runs"][-1]["files"], removed)
        second = self.run_cleanup()
        self.assertEqual(second["runs"][-1]["freed"], 0)
        self.assertEqual(second["freed_24h"], out["freed_24h"])

    def test_failed_unlink_is_not_counted(self):
        path = self.old_file("redut-kept.tmp")
        out = self.run_cleanup(fail_command="delete")
        self.assertTrue(path.exists())
        self.assertEqual(out["runs"][-1]["freed"], 0)

    def test_failed_log_replace_is_not_counted(self):
        data = b"line\n" * 350
        self.logs[0].write_bytes(data)
        out = self.run_cleanup(fail_command="mv")
        self.assertEqual(self.logs[0].read_bytes(), data)
        self.assertEqual(out["runs"][-1]["freed"], 0)

    def test_parallel_invocation_does_not_double_count(self):
        import fcntl
        with (self.state / "cleanup.lock").open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertIsNone(self.run_cleanup())


if __name__ == "__main__":
    unittest.main(verbosity=2)
