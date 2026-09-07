# -*- coding: utf-8 -*-
"""Behavioral checks for the watchdog's read-only policy-path trigger."""
import os
import shutil
import subprocess
import tempfile
import unittest

import _ctx  # noqa: F401


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(os.path.dirname(ROOT), "install", "templates",
                      "singbox-watchdog.sh")
BASH = (shutil.which("bash")
        or (r"C:\Program Files\Git\bin\bash.exe"
            if os.path.isfile(r"C:\Program Files\Git\bin\bash.exe") else None))


@unittest.skipUnless(BASH, "bash is required for watchdog contract")
class TestWatchdogPolicyPath(unittest.TestCase):
    def check(self, rules, marked, defaults="default dev tun0 scope link\n",
              rule_rc=0, marked_rc=0, defaults_rc=0):
        with tempfile.TemporaryDirectory() as tmp:
            fake_ip = os.path.join(tmp, "ip")
            with open(fake_ip, "w", encoding="utf-8", newline="\n") as handle:
                handle.write("""#!/bin/sh
if [ \"$1 $2 $3 $4 $5 $6\" = \"-4 route show table middleman default\" ]; then
    printf '%s' \"$TEST_DEFAULTS\"; exit \"$TEST_DEFAULTS_RC\"
fi
if [ \"$1 $2 $3\" = \"-4 rule show\" ]; then
    printf '%s' \"$TEST_RULES\"; exit \"$TEST_RULES_RC\"
fi
if [ \"$1 $2 $3 $4 $5 $6\" = \"-4 route get 8.8.8.8 mark 0x64\" ]; then
    printf '%s' \"$TEST_MARKED\"; exit \"$TEST_MARKED_RC\"
fi
exit 97
""")
            os.chmod(fake_ip, 0o755)
            env = dict(os.environ, REDUT_WATCHDOG_SOURCE_ONLY="1",
                       TEST_DEFAULTS=defaults, TEST_DEFAULTS_RC=str(defaults_rc),
                       TEST_RULES=rules, TEST_RULES_RC=str(rule_rc),
                       TEST_MARKED=marked, TEST_MARKED_RC=str(marked_rc))
            command = 'source "$1"; IP="$2"; policy_path_ok'
            return subprocess.run(
                [BASH, "-c", command, "watchdog-test", SCRIPT, fake_ip],
                env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=False).returncode == 0

    def test_healthy_exact_path_passes(self):
        self.assertTrue(self.check(
            "100: from all fwmark 0x64 lookup middleman\n",
            "8.8.8.8 dev tun0 table middleman src 198.18.0.1 mark 0x64\n"))

    def test_missing_or_duplicate_rule_delegates(self):
        exact = "100: from all fwmark 0x64 lookup middleman\n"
        for rules in ("", exact + exact):
            with self.subTest(rules=rules):
                self.assertFalse(self.check(
                    rules,
                    "8.8.8.8 dev tun0 table middleman src 198.18.0.1 mark 0x64\n"))

    def test_wrong_effective_lookup_and_duplicate_default_delegate(self):
        rule = "100: from all fwmark 0x64 lookup middleman\n"
        self.assertFalse(self.check(
            rule, "8.8.8.8 via 192.0.2.1 dev ens3 src 192.0.2.10 mark 0x64\n"))
        self.assertFalse(self.check(
            rule, "8.8.8.8 dev tun0 table middleman mark 0x64\n",
            defaults="default dev tun0\ndefault via 192.0.2.1 dev ens3\n"))

    def test_any_inspection_error_delegates(self):
        rule = "100: from all fwmark 0x64 lookup middleman\n"
        marked = "8.8.8.8 dev tun0 table middleman mark 0x64\n"
        for kwargs in ({"defaults_rc": 2}, {"rule_rc": 2}, {"marked_rc": 2}):
            with self.subTest(kwargs=kwargs):
                self.assertFalse(self.check(rule, marked, **kwargs))
