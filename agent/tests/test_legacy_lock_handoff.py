# -*- coding: utf-8 -*-
"""A01: verified lock migration from the executing legacy updater process."""
import builtins
import importlib.util
import io
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import _ctx  # noqa: F401


ROOT = pathlib.Path(__file__).resolve().parents[2]
HELPER = ROOT / "install" / "legacy_lock_handoff.py"
SPEC = importlib.util.spec_from_file_location("legacy_lock_handoff", HELPER)
handoff = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(handoff)


class TestLegacyLockProof(unittest.TestCase):
    def test_proc_lock_parser_requires_exact_exclusive_flock_owner_and_inode(self):
        rows = """\
11: POSIX  ADVISORY  WRITE 4242 00:2a:999 0 EOF
12: FLOCK  ADVISORY  READ  4242 00:2a:777 0 EOF
13: FLOCK  ADVISORY  WRITE 9999 00:2a:777 0 EOF
14: FLOCK  ADVISORY  WRITE 4242 00:2a:777 0 EOF
"""
        with mock.patch.object(handoff, "_lock_tuple", return_value=(0, 42, 777)), \
             mock.patch.object(builtins, "open",
                               side_effect=lambda *_args, **_kwargs: io.StringIO(rows)):
            self.assertTrue(handoff._owner_has_kernel_flock(4242, "/run/test.lock"))
            self.assertFalse(handoff._owner_has_kernel_flock(4243, "/run/test.lock"))

    def test_parent_fd_scan_keeps_only_same_device_and_inode(self):
        stats = {"/lock": SimpleNamespace(st_dev=9, st_ino=77),
                 os.path.join("/proc/42/fd", "3"):
                     SimpleNamespace(st_dev=9, st_ino=77),
                 os.path.join("/proc/42/fd", "4"):
                     SimpleNamespace(st_dev=9, st_ino=78)}
        with mock.patch.object(handoff.os, "listdir", return_value=["4", "x", "3"]), \
             mock.patch.object(handoff.os, "stat", side_effect=lambda path: stats[path]):
            self.assertEqual(handoff._owner_lock_fds(42, "/lock"), [3])

    def test_non_linux_host_is_rejected_before_any_handoff(self):
        with mock.patch.object(handoff.os, "name", "nt"):
            with self.assertRaisesRegex(RuntimeError, "Linux/x86_64"):
                handoff.main(["--owner", "42", "--lock", "/run/test.lock",
                              "--script", "/tmp/setup.sh"])

    def test_one_pinned_pidfd_is_reused_for_every_candidate(self):
        fake_fcntl = SimpleNamespace(
            LOCK_EX=1, LOCK_NB=2, flock=mock.Mock(side_effect=[OSError("wrong OFD"), None]))
        with mock.patch.object(handoff.os, "name", "posix"), \
             mock.patch.object(handoff, "fcntl", fake_fcntl), \
             mock.patch.object(handoff.platform, "machine", return_value="x86_64"), \
             mock.patch.object(handoff.os, "getppid", side_effect=[42, 42]), \
             mock.patch.object(handoff.os, "pidfd_open", return_value=91,
                               create=True) as pidfd_open, \
             mock.patch.object(handoff.os.path, "realpath", side_effect=lambda value: value), \
             mock.patch.object(handoff.os.path, "isfile", return_value=True), \
             mock.patch.object(handoff, "_owner_lock_fds", return_value=[3, 7]), \
             mock.patch.object(handoff, "_owner_has_kernel_flock", return_value=True), \
             mock.patch.object(handoff, "_pidfd_getfd", side_effect=[30, 70]) as getfd, \
             mock.patch.object(handoff.os, "set_inheritable"), \
             mock.patch.object(handoff.os, "close") as close, \
             mock.patch.object(handoff.os, "execve", side_effect=RuntimeError("exec")):
            with self.assertRaisesRegex(RuntimeError, "exec"):
                handoff.main(["--owner", "42", "--lock", "/run/test.lock",
                              "--script", "/tmp/setup.sh"])
        pidfd_open.assert_called_once_with(42, 0)
        self.assertEqual(getfd.call_args_list, [mock.call(91, 3), mock.call(91, 7)])
        self.assertIn(mock.call(91), close.call_args_list)

    def test_all_candidates_are_duplicated_before_any_lock_probe(self):
        events = []

        def duplicate(_pidfd, owner_fd):
            events.append(("duplicate", owner_fd))
            return owner_fd * 10

        def probe(candidate, _flags):
            events.append(("probe", candidate))
            if candidate == 30:
                raise OSError("wrong OFD")

        fake_fcntl = SimpleNamespace(LOCK_EX=1, LOCK_NB=2, flock=probe)
        with mock.patch.object(handoff.os, "name", "posix"), \
             mock.patch.object(handoff, "fcntl", fake_fcntl), \
             mock.patch.object(handoff.platform, "machine", return_value="x86_64"), \
             mock.patch.object(handoff.os, "getppid", side_effect=[42, 42]), \
             mock.patch.object(handoff.os, "pidfd_open", return_value=91, create=True), \
             mock.patch.object(handoff.os.path, "realpath", side_effect=lambda value: value), \
             mock.patch.object(handoff.os.path, "isfile", return_value=True), \
             mock.patch.object(handoff, "_owner_lock_fds", return_value=[3, 7]), \
             mock.patch.object(handoff, "_owner_has_kernel_flock", return_value=True), \
             mock.patch.object(handoff, "_pidfd_getfd", side_effect=duplicate), \
             mock.patch.object(handoff.os, "set_inheritable"), \
             mock.patch.object(handoff.os, "close"), \
             mock.patch.object(handoff.os, "execve", side_effect=RuntimeError("exec")):
            with self.assertRaisesRegex(RuntimeError, "exec"):
                handoff.main(["--owner", "42", "--lock", "/run/test.lock",
                              "--script", "/tmp/setup.sh"])
        self.assertEqual(events, [("duplicate", 3), ("duplicate", 7),
                                  ("probe", 30), ("probe", 70)])

    def test_partial_candidate_set_is_closed_if_any_duplication_fails(self):
        fake_fcntl = SimpleNamespace(LOCK_EX=1, LOCK_NB=2, flock=mock.Mock())
        with mock.patch.object(handoff.os, "name", "posix"), \
             mock.patch.object(handoff, "fcntl", fake_fcntl), \
             mock.patch.object(handoff.platform, "machine", return_value="x86_64"), \
             mock.patch.object(handoff.os, "getppid", side_effect=[42, 42]), \
             mock.patch.object(handoff.os, "pidfd_open", return_value=91, create=True), \
             mock.patch.object(handoff.os.path, "realpath", side_effect=lambda value: value), \
             mock.patch.object(handoff.os.path, "isfile", return_value=True), \
             mock.patch.object(handoff, "_owner_lock_fds", return_value=[3, 7]), \
             mock.patch.object(handoff, "_owner_has_kernel_flock", return_value=True), \
             mock.patch.object(handoff, "_pidfd_getfd",
                               side_effect=[30, OSError("parent exited")]), \
             mock.patch.object(handoff.os, "close") as close:
            with self.assertRaisesRegex(OSError, "parent exited"):
                handoff.main(["--owner", "42", "--lock", "/run/test.lock",
                              "--script", "/tmp/setup.sh"])
        self.assertIn(mock.call(30), close.call_args_list)
        self.assertIn(mock.call(91), close.call_args_list)
        fake_fcntl.flock.assert_not_called()

    def test_parent_death_after_pidfd_open_fails_before_proc_lock_proof(self):
        fake_fcntl = SimpleNamespace(LOCK_EX=1, LOCK_NB=2, flock=mock.Mock())
        with mock.patch.object(handoff.os, "name", "posix"), \
             mock.patch.object(handoff, "fcntl", fake_fcntl), \
             mock.patch.object(handoff.platform, "machine", return_value="x86_64"), \
             mock.patch.object(handoff.os, "getppid", side_effect=[42, 1]), \
             mock.patch.object(handoff.os, "pidfd_open", return_value=91,
                               create=True), \
             mock.patch.object(handoff, "_owner_lock_fds") as scan, \
             mock.patch.object(handoff.os, "close"):
            with self.assertRaisesRegex(RuntimeError, "died before lock handoff"):
                handoff.main(["--owner", "42", "--lock", "/run/test.lock",
                              "--script", "/tmp/setup.sh"])
        scan.assert_not_called()

    def test_setup_revalidates_descriptor_and_never_trusts_flag_alone(self):
        setup = ROOT / "setup.sh"
        if not setup.is_file():
            setup = ROOT / "install" / "setup.sh"
        text = setup.read_text(encoding="utf-8")
        self.assertIn('readlink "/proc/$$/fd/$LOCK_FD"', text)
        self.assertIn('flock -n "$LOCK_FD"', text)
        self.assertIn("legacy_lock_handoff.py", text)
        self.assertIn('os.getppid() != args.owner', HELPER.read_text(encoding="utf-8"))


@unittest.skipUnless(os.name == "posix" and hasattr(os, "pidfd_open"),
                     "real pidfd/flock handoff requires Linux")
class TestLinuxLegacyProcessHandoff(unittest.TestCase):
    def test_parent_owned_flock_is_same_open_description_in_new_setup(self):
        import fcntl
        with tempfile.TemporaryDirectory() as tmp:
            lock_path = os.path.realpath(os.path.join(tmp, "vpn-agent.lock"))
            marker = os.path.join(tmp, "marker")
            setup = os.path.realpath(os.path.join(tmp, "setup.sh"))
            with open(setup, "w", encoding="utf-8") as target:
                target.write(
                    "#!/bin/bash\nset -eu\n"
                    "test \"${REDUT_LOCK_HANDOFF:-}\" = legacy-pidfd-v1\n"
                    "test \"$(readlink /proc/$$/fd/$REDUT_LOCK_FD)\" = \"$1\"\n"
                    "flock -n \"$REDUT_LOCK_FD\"\n"
                    "printf LOCK_CONFIRMED >\"$2\"\n")
            with open(lock_path, "a", encoding="ascii") as owner:
                fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
                run = subprocess.run(
                    [sys.executable, str(HELPER), "--owner", str(os.getpid()),
                     "--lock", lock_path, "--script", setup, "--",
                     lock_path, marker], capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(pathlib.Path(marker).read_text(encoding="ascii"),
                             "LOCK_CONFIRMED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
