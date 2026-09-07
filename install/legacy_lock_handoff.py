#!/usr/bin/env python3
"""Verified lock handoff from Redut 1.12.3/1.13.0 updater to new setup.

Those updaters keep /run/vpn-agent.lock open while waiting for setup.sh, but
do not pass that descriptor through exec.  On Linux/x86_64 pidfd_getfd copies
the *same open file description*, so the kernel flock remains continuous even
if either process is killed.  Every check here is based on /proc and the kernel
lock table; no REDUT_* environment value is accepted as proof.
"""
import argparse
import ctypes
import errno
import os
import platform
import sys

try:
    import fcntl
except ImportError:  # Allows static/unit validation from the Windows dev host.
    fcntl = None


SYS_PIDFD_GETFD_X86_64 = 438


def _lock_tuple(path):
    st = os.stat(path)
    return os.major(st.st_dev), os.minor(st.st_dev), st.st_ino


def _owner_has_kernel_flock(owner_pid, lock_path):
    expected = _lock_tuple(lock_path)
    try:
        with open("/proc/locks", encoding="ascii", errors="replace") as source:
            lines = source.readlines()
    except OSError:
        return False
    for line in lines:
        fields = line.split()
        if len(fields) < 8 or fields[1:4] != ["FLOCK", "ADVISORY", "WRITE"]:
            continue
        try:
            pid = int(fields[4])
            major, minor, inode = fields[5].split(":", 2)
            identity = int(major, 16), int(minor, 16), int(inode)
        except (TypeError, ValueError):
            continue
        if pid == owner_pid and identity == expected:
            return True
    return False


def _owner_lock_fds(owner_pid, lock_path):
    expected = os.stat(lock_path)
    fd_dir = "/proc/%d/fd" % owner_pid
    try:
        names = os.listdir(fd_dir)
    except OSError as error:
        raise RuntimeError("legacy updater fd table unavailable: %s" % error) from error
    matches = []
    for name in names:
        if not name.isdigit():
            continue
        try:
            current = os.stat(os.path.join(fd_dir, name))
        except OSError:
            continue
        if current.st_dev == expected.st_dev and current.st_ino == expected.st_ino:
            matches.append(int(name))
    if not matches:
        raise RuntimeError("legacy updater has no descriptor for the network lock")
    return sorted(matches)


def _pidfd_getfd(pidfd, target_fd):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    copied = libc.syscall(SYS_PIDFD_GETFD_X86_64, pidfd, target_fd, 0)
    if copied < 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    return int(copied)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--owner", type=int, required=True)
    parser.add_argument("--lock", required=True)
    parser.add_argument("--script", required=True)
    parser.add_argument("script_args", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if os.name != "posix" or fcntl is None or platform.machine() != "x86_64":
        raise RuntimeError("legacy lock handoff requires Linux/x86_64")
    if not hasattr(os, "pidfd_open"):
        raise RuntimeError("kernel/Python does not expose pidfd_open")
    if args.owner <= 1 or os.getppid() != args.owner:
        raise RuntimeError("legacy lock owner is not the direct updater parent")
    # Pin the process identity before any /proc-by-number inspection. A second
    # PPID check closes the death/reparent window around pidfd_open; all getfd
    # calls below reuse this pidfd, so PID reuse can never redirect the proof.
    pidfd = os.pidfd_open(args.owner, 0)
    inherited_fd = None
    candidates = []
    try:
        if os.getppid() != args.owner:
            raise RuntimeError("legacy updater parent died before lock handoff")
        lock_path = os.path.realpath(args.lock)
        if lock_path != args.lock or not os.path.isfile(lock_path):
            raise RuntimeError("network lock path is missing or not canonical")
        script_path = os.path.realpath(args.script)
        if script_path != args.script or not os.path.isfile(script_path):
            raise RuntimeError("setup path is missing or not canonical")
        owner_fds = _owner_lock_fds(args.owner, lock_path)
        if not _owner_has_kernel_flock(args.owner, lock_path):
            raise RuntimeError("legacy updater does not own the exclusive kernel flock")
        # Duplicate every same-inode descriptor before probing any of them.  In
        # the multi-FD case this guarantees that the locked OFD is already held
        # by this process if the parent dies between duplication and probing;
        # otherwise an unlocked candidate could acquire a freshly released
        # lock and be mistaken for a continuous handoff.
        try:
            for owner_fd in owner_fds:
                candidate = _pidfd_getfd(pidfd, owner_fd)
                candidates.append(candidate)
        except BaseException:
            for candidate in candidates:
                os.close(candidate)
            raise
    finally:
        os.close(pidfd)
    last_error = None
    # Only the descriptor sharing the parent's locked open-file description
    # can reassert LOCK_EX while all candidate OFDs remain open.
    for candidate in candidates:
        try:
            fcntl.flock(candidate, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            last_error = error
            continue
        inherited_fd = candidate
        break
    if inherited_fd is None:
        for candidate in candidates:
            os.close(candidate)
        if last_error is not None:
            raise last_error
        raise RuntimeError("could not duplicate the updater's locked descriptor")
    for candidate in candidates:
        if candidate != inherited_fd:
            os.close(candidate)
    try:
        os.set_inheritable(inherited_fd, True)
        env = dict(os.environ)
        env.update(REDUT_LOCK_HELD="1", REDUT_LOCK_FD=str(inherited_fd),
                   REDUT_LOCK_HANDOFF="legacy-pidfd-v1")
        tail = list(args.script_args)
        if tail[:1] == ["--"]:
            tail = tail[1:]
        os.execve("/bin/bash", ["bash", script_path] + tail, env)
    except BaseException:
        os.close(inherited_fd)
        raise


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("legacy updater lock handoff failed: %s" % error, file=sys.stderr)
        sys.exit(75 if isinstance(error, OSError) and error.errno in
                 (errno.EPERM, errno.ENOSYS, errno.ESRCH) else 1)
