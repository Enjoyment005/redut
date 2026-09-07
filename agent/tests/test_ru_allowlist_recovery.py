# -*- coding: utf-8 -*-
"""A08: execute the real RU updater across crash/reboot rollback boundaries."""
import json
import ctypes
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

import _ctx  # noqa: F401


ROOT = pathlib.Path(__file__).resolve().parents[2]
UPDATER = ROOT / "install" / "templates" / "update-ru-whitelist.sh"


def _bash_path():
    found = shutil.which("bash")
    if found:
        return found
    candidate = pathlib.Path(r"C:\Program Files\Git\bin\bash.exe")
    return str(candidate) if candidate.is_file() else None


BASH = _bash_path()


@unittest.skipUnless(BASH, "bash is required for the executable RU rollback harness")
class TestRUAllowlistCrashRecovery(unittest.TestCase):
    CRASH_POINTS = (
        "prepared",
        "after-swap-before-marker",
        "ipset-swapped",
        "after-conf-move",
        "after-net-move",
        "files-installed",
        "after-restart",
        "after-domain-flush",
    )
    ROLLBACK_CRASH_POINTS = (
        "rollback-marked",
        "rollback-set-converged",
        "rollback-files-restored",
        "rollback-restarted",
        "rollback-domain-flushed",
    )

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.bin = self.root / "bin"
        self.state = self.root / "kernel-sets"
        self.etc = self.root / "etc"
        self.var = self.root / "var"
        for path in (self.bin, self.state, self.etc, self.var):
            path.mkdir(parents=True, exist_ok=True)
        self._write_fake_commands()
        self.script = self.root / "update-ru-whitelist.sh"
        self.script.write_text(self._instrumented_script(), encoding="utf-8", newline="\n")
        self.script.chmod(0o755)
        self.conf = self.etc / "ru-whitelist.conf"
        self.net = self.etc / "ru_whitelist_net.ipset"
        self.log = self.var / "ru-whitelist-update.log"
        self.marker = self.var / "ru-whitelist-update.pending"
        self.lkg = self.var / "ru-whitelist-lkg"
        self.curl_log = self.var / "curl.log"
        self.old_conf = "server=/old.example/ru_whitelist\n"
        self.old_net = (
            "create ru_whitelist_net hash:net family inet\n"
            "add ru_whitelist_net 198.51.100.0/24\n")

    def _posix(self, path):
        path = str(path)
        if os.name != "nt":
            return path
        return subprocess.check_output(
            [BASH, "-lc", "cygpath -u \"$1\"", "bash", path],
            text=True).strip()

    def _write(self, name, text):
        target = self.bin / name
        target.write_text(text, encoding="utf-8", newline="\n")
        target.chmod(0o755)

    def _write_fake_commands(self):
        python = sys.executable
        if os.name == "nt":
            buffer = ctypes.create_unicode_buffer(32768)
            if ctypes.windll.kernel32.GetShortPathNameW(python, buffer, len(buffer)):
                python = buffer.value
        self._write("python3", '#!/bin/sh\nexec "%s" "$@"\n'
                    % self._posix(python).replace('"', '\\"'))
        self._write("flock", "#!/bin/sh\nexit 0\n")
        self._write("dnsmasq", "#!/bin/sh\nexit 0\n")
        self._write("curl", """#!/bin/sh
set -eu
: "${CURL_LOG:?}"
printf '%s\n' "$*" >> "$CURL_LOG"
out=""
url=""
while [ "$#" -gt 0 ]; do
    if [ "$1" = "-o" ]; then out="$2"; shift 2; continue; fi
    case "$1" in https://*) url="$1" ;; esac
    shift
done
case "$url" in
  */whitelist.txt) printf 'alpha.example\nbeta.example\n' > "$out" ;;
  */ipwhitelist.txt) printf '8.8.8.8\n1.1.1.1\n' > "$out" ;;
  */cidrwhitelist.txt) printf '9.9.9.0/24\n' > "$out" ;;
  *) exit 90 ;;
esac
""")
        self._write("sha256sum", """#!/bin/sh
if [ "${1:-}" = "--check" ]; then cat >/dev/null; exit 0; fi
exec /usr/bin/sha256sum "$@"
""")
        self._write("systemctl", """#!/bin/sh
set -eu
: "${SYSTEMCTL_PID:?}"
case " $* " in
  *" show "*) cat "$SYSTEMCTL_PID" ;;
  *" restart "*)
    [ "${REDUT_TEST_FAIL:-}" != "restart" ] || exit 70
    n=$(cat "$SYSTEMCTL_PID"); echo $((n + 1)) > "$SYSTEMCTL_PID"
    ;;
  *" is-active "*) exit 0 ;;
  *) exit 91 ;;
esac
""")
        self._write("ipset", """#!/bin/sh
set -eu
: "${IPSET_STATE:?}"
cmd="${1:-}"; shift || true
case "$cmd" in
  list)
    [ "${1:-}" = "-n" ] || exit 2
    names=""
    for item in "$IPSET_STATE"/*; do
      [ -f "$item" ] && names="$names ${item##*/}"
    done
    [ -z "$names" ] || printf '%s\n' $names
    ;;
  save)
    name="$1"; file="$IPSET_STATE/$name"; [ -f "$file" ] || exit 1
    echo "create $name hash:net family inet"
    while IFS= read -r member; do [ -n "$member" ] && echo "add $name $member"; done < "$file"
    ;;
  restore)
    while IFS= read -r line; do
      set -- $line
      case "${1:-}" in
        create) : > "$IPSET_STATE/$2" ;;
        add) echo "$3" >> "$IPSET_STATE/$2" ;;
        '') ;;
        *) exit 2 ;;
      esac
    done
    ;;
  create)
    [ "${REDUT_TEST_FAIL:-}" != "create" ] || exit 70
    name="$1"; [ ! -e "$IPSET_STATE/$name" ] || exit 1; : > "$IPSET_STATE/$name"
    ;;
  destroy)
    name="$1"; [ -e "$IPSET_STATE/$name" ] || exit 1; rm -f "$IPSET_STATE/$name"
    ;;
  flush)
    name="$1"; [ -e "$IPSET_STATE/$name" ] || exit 1; : > "$IPSET_STATE/$name"
    ;;
  swap)
    [ "${REDUT_TEST_FAIL:-}" != "swap" ] || exit 70
    a="$1"; b="$2"; [ -f "$IPSET_STATE/$a" ] && [ -f "$IPSET_STATE/$b" ] || exit 1
    mv "$IPSET_STATE/$a" "$IPSET_STATE/.swap"
    mv "$IPSET_STATE/$b" "$IPSET_STATE/$a"
    mv "$IPSET_STATE/.swap" "$IPSET_STATE/$b"
    ;;
  *) exit 2 ;;
esac
""")

    @staticmethod
    def _insert_after_last(text, token, addition):
        pos = text.rfind(token)
        if pos < 0:
            raise AssertionError("missing updater token: %s" % token)
        pos += len(token)
        return text[:pos] + addition + text[pos:]

    def _instrumented_script(self):
        text = UPDATER.read_text(encoding="utf-8")
        replacements = {
            'CONF_FILE="/etc/dnsmasq.d/ru-whitelist.conf"':
                'CONF_FILE="%s"' % self._posix(self.etc / "ru-whitelist.conf"),
            'NET_FILE="/etc/ru_whitelist_net.ipset"':
                'NET_FILE="%s"' % self._posix(self.etc / "ru_whitelist_net.ipset"),
            'LKG_DIR="/var/lib/vpn-panel/ru-whitelist-lkg"':
                'LKG_DIR="%s"' % self._posix(self.var / "ru-whitelist-lkg"),
            'LOG="/var/log/ru-whitelist-update.log"':
                'LOG="%s"' % self._posix(self.var / "ru-whitelist-update.log"),
            'TXN_MARK="/var/lib/vpn-panel/ru-whitelist-update.pending"':
                'TXN_MARK="%s"' % self._posix(self.var / "ru-whitelist-update.pending"),
            'mkdir -p /var/lib/vpn-panel': 'mkdir -p "%s"' % self._posix(self.var),
            '/run/vpn-agent.lock': self._posix(self.var / "vpn-agent.lock"),
            'if not 800 <= len(domains) <= 2000:':
                'if not 2 <= len(domains) <= 20:',
            'if not 20000 <= len(collapsed) <= 50000 or coverage > 50000000:':
                'if not 2 <= len(collapsed) <= 20 or coverage > 50000000:',
        }
        for old, new in replacements.items():
            if old not in text:
                raise AssertionError("updater fixture drift: %s" % old)
            text = text.replace(old, new)
        # Windows cannot open/fsync directory descriptors with the POSIX
        # semantics used on Debian. Keep the production helper untouched and
        # model a successful durability barrier in this cross-platform harness.
        start = text.index("fsync_paths(){")
        end = text.index("\n}\n\nset_mark(){", start) + 2
        text = text[:start] + "fsync_paths(){ :; }" + text[end:]
        hook = """
fault(){
    if [ "${REDUT_TEST_CRASH_POINT:-}" = "$1" ]; then
        trap - EXIT
        exit 99
    fi
}
"""
        text = text.replace('TMP="$(mktemp -d)"\n', 'TMP="$(mktemp -d)"\n' + hook, 1)
        text = self._insert_after_last(text, "set_mark prepared\n", "fault prepared\n")
        text = text.replace(
            '    fi\n    if [ "$old_hash" = "ABSENT" ]; then',
            '    fi\n    fault rollback-marked\n'
            '    if [ "$old_hash" = "ABSENT" ]; then', 1)
        text = text.replace(
            '        fi\n    fi\n    if ! restore_files; then',
            '        fi\n    fi\n    fault rollback-set-converged\n'
            '    if ! restore_files; then', 1)
        text = text.replace(
            '    fi\n    if ! fsync_paths "$CONF_FILE" "$NET_FILE" \\\n',
            '    fi\n    fault rollback-files-restored\n'
            '    if ! fsync_paths "$CONF_FILE" "$NET_FILE" \\\n', 1)
        text = text.replace(
            '    fi\n    # A killed forward transaction may have reloaded the new domains',
            '    fi\n    fault rollback-restarted\n'
            '    # A killed forward transaction may have reloaded the new domains', 1)
        text = text.replace(
            '    fi\n    # The pending marker is the durable transaction boundary.',
            '    fi\n    fault rollback-domain-flushed\n'
            '    # The pending marker is the durable transaction boundary.', 1)
        text = self._insert_after_last(
            text, 'ipset swap "${NET_SET}_candidate" "$NET_SET"\n',
            "fault after-swap-before-marker\n")
        text = self._insert_after_last(
            text, "set_mark ipset_swapped\n", "fault ipset-swapped\n")
        text = self._insert_after_last(
            text, 'mv "$CONF_FILE.candidate" "$CONF_FILE"\n',
            "fault after-conf-move\n")
        text = self._insert_after_last(
            text, 'mv "$NET_FILE.candidate" "$NET_FILE"\n',
            "fault after-net-move\n")
        text = self._insert_after_last(
            text, "set_mark files_installed\n", "fault files-installed\n")
        marker = "fi\n# Dynamic domain answers belong to the previous bundle."
        text = text.replace(
            marker,
            "fi\nfault after-restart\n# Dynamic domain answers belong to the previous bundle.",
            1)
        marker = "fi\n# Commit becomes durable only after the pending marker deletion"
        text = text.replace(
            marker,
            "fi\nfault after-domain-flush\n# Commit becomes durable only after the pending marker deletion",
            1)
        text = self._insert_after_last(
            text,
            '    log "ОШИБКА: commit marker не удалён; generation will be rolled back"; exit 1\nfi\n',
            "fault commit-marker-removed\n")
        return text

    def _env(self, crash_point="", fail=""):
        pid = self.var / "dnsmasq.pid"
        if not pid.exists():
            pid.write_text("100\n", encoding="ascii")
        env = dict(os.environ)
        env.update({
            # Do not append Windows' semicolon-separated PATH: MSYS can
            # reinterpret it and bypass the deterministic fake curl/ipset.
            # Git for Windows prepends /mingw64/bin when bash.exe starts, so
            # _run resets PATH again inside the already-running shell.
            "REDUT_TEST_PATH": self._posix(self.bin) + ":/usr/bin:/bin",
            "IPSET_STATE": self._posix(self.state),
            "SYSTEMCTL_PID": self._posix(pid),
            "CURL_LOG": self._posix(self.curl_log),
            "REDUT_TEST_CRASH_POINT": crash_point,
            "REDUT_TEST_FAIL": fail,
        })
        return env

    def _run(self, *args, crash_point="", fail=""):
        return subprocess.run(
            [BASH, "-c",
             'PATH="$REDUT_TEST_PATH"; export PATH; exec "$@"',
             "redut-test", self._posix(self.script), *args],
            env=self._env(crash_point, fail), capture_output=True, text=True,
            encoding="utf-8", errors="replace",
            timeout=30)

    def _seed_old_generation(self):
        self.conf.write_text(self.old_conf, encoding="utf-8", newline="\n")
        self.net.write_text(self.old_net, encoding="utf-8", newline="\n")
        (self.state / "ru_whitelist_net").write_text(
            "198.51.100.0/24\n", encoding="ascii")
        (self.state / "ru_whitelist").write_text(
            "203.0.113.10\n", encoding="ascii")

    def _assert_old_generation(self):
        self.assertEqual(self.conf.read_text(encoding="utf-8"), self.old_conf)
        self.assertEqual(self.net.read_text(encoding="utf-8"), self.old_net)
        self.assertEqual(
            (self.state / "ru_whitelist_net").read_text(encoding="ascii"),
            "198.51.100.0/24\n")
        self.assertFalse((self.state / "ru_whitelist_net_candidate").exists())
        self.assertFalse(self.marker.exists())

    def test_every_forward_boundary_recovers_offline_after_all_kernel_sets_are_lost(self):
        for crash_point in self.CRASH_POINTS:
            with self.subTest(crash_point=crash_point):
                for path in (self.state, self.etc, self.var):
                    shutil.rmtree(path)
                    path.mkdir(parents=True)
                self._seed_old_generation()
                crashed = self._run(crash_point=crash_point)
                self.assertEqual(crashed.returncode, 99, crashed.stdout + crashed.stderr)
                self.assertTrue(self.marker.exists(), crash_point)

                # A reboot loses every volatile set, including both live and
                # candidate. Recovery must use only the durable old snapshot.
                shutil.rmtree(self.state)
                self.state.mkdir()
                if self.curl_log.exists():
                    self.curl_log.unlink()
                recovered = self._run("--recover-only")
                self.assertEqual(recovered.returncode, 0,
                                 recovered.stdout + recovered.stderr)
                self._assert_old_generation()
                self.assertFalse(self.curl_log.exists(),
                                 "recover-only must not perform a network fetch")

                repeated = self._run("--recover-only")
                self.assertEqual(repeated.returncode, 0,
                                 repeated.stdout + repeated.stderr)
                self._assert_old_generation()

    def test_rollback_flushes_answers_learned_from_abandoned_domain_generation(self):
        self._seed_old_generation()
        crashed = self._run(crash_point="files-installed")
        self.assertEqual(crashed.returncode, 99, crashed.stdout + crashed.stderr)
        self.assertTrue((self.state / "ru_whitelist").read_text(encoding="ascii"))
        recovered = self._run("--recover-only")
        self.assertEqual(recovered.returncode, 0, recovered.stdout + recovered.stderr)
        self._assert_old_generation()
        self.assertEqual((self.state / "ru_whitelist").read_text(encoding="ascii"), "")

    def test_rollback_retries_after_create_swap_and_restart_failures(self):
        for operation in ("create", "swap", "restart"):
            with self.subTest(operation=operation):
                for path in (self.state, self.etc, self.var):
                    shutil.rmtree(path)
                    path.mkdir(parents=True)
                self._seed_old_generation()
                crashed = self._run(crash_point="files-installed")
                self.assertEqual(crashed.returncode, 99,
                                 crashed.stdout + crashed.stderr)
                shutil.rmtree(self.state)
                self.state.mkdir()
                failed = self._run("--recover-only", fail=operation)
                self.assertNotEqual(failed.returncode, 0,
                                    "injected %s failure was ignored" % operation)
                self.assertTrue(self.marker.exists())
                recovered = self._run("--recover-only")
                self.assertEqual(recovered.returncode, 0,
                                 recovered.stdout + recovered.stderr)
                self._assert_old_generation()

    def test_old_static_set_absent_is_restored_as_absent(self):
        self.conf.write_text(self.old_conf, encoding="utf-8", newline="\n")
        self.net.write_text(self.old_net, encoding="utf-8", newline="\n")
        (self.state / "ru_whitelist").write_text("203.0.113.10\n", encoding="ascii")
        crashed = self._run(crash_point="files-installed")
        self.assertEqual(crashed.returncode, 99, crashed.stdout + crashed.stderr)
        self.assertEqual((self.lkg / ".old_set_hash").read_text().strip(), "ABSENT")
        shutil.rmtree(self.state)
        self.state.mkdir()
        recovered = self._run("--recover-only")
        self.assertEqual(recovered.returncode, 0, recovered.stdout + recovered.stderr)
        self.assertEqual(self.conf.read_text(encoding="utf-8"), self.old_conf)
        self.assertEqual(self.net.read_text(encoding="utf-8"), self.old_net)
        self.assertFalse((self.state / "ru_whitelist_net").exists())
        self.assertFalse(self.marker.exists())

    def test_repeated_crash_inside_rollback_converges_on_next_boot(self):
        for crash_point in self.ROLLBACK_CRASH_POINTS:
            with self.subTest(crash_point=crash_point):
                for path in (self.state, self.etc, self.var):
                    shutil.rmtree(path)
                    path.mkdir(parents=True)
                self._seed_old_generation()
                forward = self._run(crash_point="files-installed")
                self.assertEqual(forward.returncode, 99,
                                 forward.stdout + forward.stderr)
                shutil.rmtree(self.state)
                self.state.mkdir()
                interrupted = self._run("--recover-only", crash_point=crash_point)
                self.assertEqual(interrupted.returncode, 99,
                                 interrupted.stdout + interrupted.stderr)
                self.assertTrue(self.marker.exists())
                recovered = self._run("--recover-only")
                self.assertEqual(recovered.returncode, 0,
                                 recovered.stdout + recovered.stderr)
                self._assert_old_generation()

    def test_crash_after_commit_marker_removal_keeps_new_generation(self):
        self._seed_old_generation()
        committed = self._run(crash_point="commit-marker-removed")
        self.assertEqual(committed.returncode, 99,
                         committed.stdout + committed.stderr)
        self.assertFalse(self.marker.exists())
        new_conf = self.conf.read_text(encoding="utf-8")
        new_net = self.net.read_text(encoding="utf-8")
        self.assertIn("alpha.example", new_conf)
        self.assertIn("9.9.9.0/24", new_net)
        if self.curl_log.exists():
            self.curl_log.unlink()
        recovered = self._run("--recover-only")
        self.assertEqual(recovered.returncode, 0,
                         recovered.stdout + recovered.stderr)
        self.assertEqual(self.conf.read_text(encoding="utf-8"), new_conf)
        self.assertEqual(self.net.read_text(encoding="utf-8"), new_net)
        self.assertFalse(self.curl_log.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
