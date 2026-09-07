# -*- coding: utf-8 -*-
"""Security regressions for the SSH deploy secret writer."""
import contextlib
import io
import os
import stat
import types
import unittest
from unittest import mock

import _ctx  # noqa: F401
import deploy


class _SecretHandle:
    def __init__(self, owner, path):
        self.owner = owner
        self.path = path
        self.item = owner.files[path]
        self.closed = False

    def chmod(self, mode):
        if self.owner.swap_path_on_handle_chmod:
            self.owner.files[self.path] = {"mode": stat.S_IFREG | 0o644, "data": ""}
        self.item["mode"] = stat.S_IFREG | mode

    def stat(self):
        attrs = {"st_mode": self.item["mode"]}
        if self.owner.expose_uid:
            attrs["st_uid"] = self.owner.uid
        return types.SimpleNamespace(**attrs)

    def write(self, data):
        self.owner.mode_at_first_write = stat.S_IMODE(self.item["mode"])
        self.item["data"] += data

    def flush(self):
        pass

    def close(self):
        self.closed = True


class _SecretSFTP:
    def __init__(self, initial_mode=0o644, uid=0, swap_path_on_handle_chmod=False,
                 expose_uid=True):
        self.initial_mode = initial_mode
        self.uid = uid
        self.swap_path_on_handle_chmod = swap_path_on_handle_chmod
        self.expose_uid = expose_uid
        self.files = {}
        self.mode_at_first_write = None

    def open(self, path, mode):
        if mode != "wx":
            raise AssertionError("secret staging must use exclusive create")
        if path in self.files:
            raise FileExistsError(path)
        self.files[path] = {"mode": stat.S_IFREG | self.initial_mode, "data": ""}
        return _SecretHandle(self, path)

    def chmod(self, path, mode):
        self.files[path]["mode"] = stat.S_IFREG | mode

    def lstat(self, path):
        item = self.files[path]
        attrs = {"st_mode": item["mode"]}
        if self.expose_uid:
            attrs["st_uid"] = self.uid
        return types.SimpleNamespace(**attrs)

    def remove(self, path):
        self.files.pop(path, None)


class TestSecretStaging(unittest.TestCase):
    @staticmethod
    def _run_remote_dns_program(*, db_present, table_present=True,
                                row_present=True, phase="idle",
                                unit="inactive", load="loaded"):
        class Connection:
            def execute(self, query, _params=()):
                if "sqlite_master" in query:
                    return types.SimpleNamespace(
                        fetchone=lambda: ((1,) if table_present else None))
                if "SELECT phase" in query:
                    return types.SimpleNamespace(
                        fetchone=lambda: ((phase,) if row_present else None))
                raise AssertionError(query)

            def close(self):
                pass

        def systemctl(command, **_kwargs):
            value = unit if "is-active" in command else load
            return types.SimpleNamespace(stdout=value + "\n", stderr="", returncode=0)

        output = io.StringIO()
        try:
            with mock.patch("os.path.lexists",
                            side_effect=lambda path: path == "/etc/vpn-panel/config.json"), \
                    mock.patch("os.path.isfile", return_value=db_present), \
                    mock.patch("builtins.open", return_value=io.StringIO("{}")), \
                    mock.patch("sqlite3.connect", return_value=Connection()), \
                    mock.patch("subprocess.run", side_effect=systemctl), \
                    contextlib.redirect_stdout(output):
                exec(deploy.REMOTE_DNS_PREFLIGHT_PROGRAM, {})
        except SystemExit as error:
            return False, str(error)
        return True, output.getvalue().strip()

    def test_mode_is_0600_before_first_secret_byte(self):
        sftp = _SecretSFTP(initial_mode=0o644)
        deploy._write_secret_staging(sftp, "/tmp/secret", "synthetic")
        self.assertEqual(sftp.mode_at_first_write, 0o600)
        self.assertEqual(sftp.files["/tmp/secret"]["data"], "synthetic")

    def test_mode_check_applies_to_written_handle_not_replaceable_path(self):
        sftp = _SecretSFTP(initial_mode=0o644, swap_path_on_handle_chmod=True)
        deploy._write_secret_staging(sftp, "/tmp/secret", "synthetic")
        self.assertEqual(sftp.mode_at_first_write, 0o600)
        self.assertEqual(sftp.files["/tmp/secret"]["data"], "")

    def test_unsafe_owner_is_rejected_and_staging_removed(self):
        sftp = _SecretSFTP(uid=1000)
        with self.assertRaises(OSError):
            deploy._write_secret_staging(sftp, "/tmp/secret", "synthetic")
        self.assertEqual(sftp.files["/tmp/secret"]["data"], "")
        self.assertIsNone(sftp.mode_at_first_write)

    def test_missing_owner_attribute_is_rejected_fail_closed(self):
        sftp = _SecretSFTP(expose_uid=False)
        with self.assertRaises(OSError):
            deploy._write_secret_staging(sftp, "/tmp/secret", "synthetic")
        self.assertIn("/tmp/secret", sftp.files,
                      "unowned staging must not be removed through an unproven path")
        self.assertIsNone(sftp.mode_at_first_write)

    def test_remote_merge_uses_secure_exclusive_temporary_file(self):
        compile(deploy.SECRET_WRITER_PROGRAM, "<remote-secret-writer>", "exec")
        text = deploy.SECRET_WRITER_PROGRAM
        self.assertIn("tempfile.mkstemp", text)
        self.assertIn('getattr(os, "O_NOFOLLOW", 0)', text)
        self.assertIn("os.fstat(source.fileno())", text)
        self.assertIn('merge_prefix = "." + os.path.basename(p)', text)
        self.assertLess(text.index("os.fchmod(fd, 0o600)"),
                        text.index("json.dump(new, target"))
        self.assertIn("cleanup_stale()", text)

    def test_remote_writer_nonzero_status_is_never_reported_as_success(self):
        sftp = _SecretSFTP()
        with mock.patch.object(deploy, "run_result",
                               side_effect=[(1, "synthetic merge failure"), (0, "")]):
            with self.assertRaises(SystemExit) as caught:
                deploy.put_secret_atomic(object(), sftp, "/tmp/secrets.json", "{}")
        self.assertIn("synthetic merge failure", str(caught.exception))

    def test_remote_writer_requires_explicit_verified_success_marker(self):
        sftp = _SecretSFTP()
        with mock.patch.object(deploy, "run_result",
                               side_effect=[(0, ""), (0, "")]):
            with self.assertRaises(SystemExit):
                deploy.put_secret_atomic(object(), sftp, "/tmp/secrets.json", "{}")

    def test_remote_writer_accepts_only_verified_success(self):
        sftp = _SecretSFTP()
        with mock.patch.object(deploy, "run_result",
                               return_value=(0, "REDUT_SECRET_WRITE_OK")):
            deploy.put_secret_atomic(object(), sftp, "/tmp/secrets.json", "{}")

    def test_transport_exception_removes_owned_uploaded_staging(self):
        sftp = _SecretSFTP()
        with mock.patch.object(deploy, "run_result", side_effect=ConnectionError("lost")):
            with self.assertRaises(ConnectionError):
                deploy.put_secret_atomic(object(), sftp, "/tmp/secrets.json", "{}")
        self.assertEqual(sftp.files, {})

    def test_config_writer_uses_common_remote_helper_and_checks_status(self):
        sftp = _SecretSFTP()
        with mock.patch.object(deploy, "run_result",
                               side_effect=[(1, "synthetic config failure"), (0, "")]):
            with self.assertRaises(SystemExit) as caught:
                deploy.put_config_atomic(object(), sftp, "/tmp/config.json", "{}", ("update",))
        self.assertIn("synthetic config failure", str(caught.exception))

    def test_remote_legacy_panel_is_restarted_after_config_failure(self):
        calls = []

        def result(_client, command, t=180):
            calls.append(command)
            if command == "systemctl is-active vpn-panel":
                return 0, "active"
            return 0, ""

        with mock.patch.object(deploy, "run_result", side_effect=result):
            with self.assertRaises(RuntimeError):
                with deploy.remote_panel_config_upgrade_barrier(object(), True):
                    calls.append("config merge")
                    raise RuntimeError("synthetic")
        self.assertEqual(calls, ["systemctl is-active vpn-panel",
                                 "systemctl stop vpn-panel", "config merge",
                                 "systemctl start vpn-panel"])

    def test_agent_only_deploy_contract_rejects_running_legacy_panel(self):
        with open(deploy.__file__, encoding="utf-8") as handle:
            source = handle.read()
        guard = source.index("if not a.with_panel:")
        first_mutation = source.index('run(c, "mkdir -p', guard)
        self.assertLess(guard, first_mutation)
        contract = source[guard:first_mutation]
        self.assertIn("LoadState", contract)
        self.assertIn("REDUT_LEGACY_PANEL", contract)
        self.assertIn("повтори деплой с --with-panel", contract)

    def test_remote_dns_preflight_is_after_lock_and_before_first_mutation(self):
        with open(deploy.__file__, encoding="utf-8") as handle:
            source = handle.read()
        main = source.index("def main(")
        locked = source.index("deploy_lock = acquire_remote_network_lock(c)", main)
        preflight = source.index("remote_dns_preflight(c)", locked)
        base_contract = source.index("require_remote_base_contract(c)", preflight)
        mutation = source.index('run(c, "mkdir -p', base_contract)
        self.assertLess(locked, preflight)
        self.assertLess(preflight, base_contract)
        self.assertLess(base_contract, mutation)
        compile(deploy.REMOTE_DNS_PREFLIGHT_PROGRAM,
                "<remote-dns-preflight>", "exec")
        program = deploy.REMOTE_DNS_PREFLIGHT_PROGRAM
        self.assertIn("SELECT phase FROM dns_rescue_state", program)
        self.assertIn('if load == "not-found"', program)
        self.assertNotIn('state not in ("active", "inactive", "failed", "unknown")',
                         program)

    def test_remote_dns_preflight_requires_exact_success(self):
        with mock.patch.object(deploy, "run_result", return_value=(1, "active")):
            with self.assertRaises(SystemExit):
                deploy.remote_dns_preflight(object())
        with mock.patch.object(deploy, "run_result", return_value=(0, "")):
            with self.assertRaises(SystemExit):
                deploy.remote_dns_preflight(object())
        with mock.patch.object(
                deploy, "run_result", return_value=(0, "REDUT_DNS_PREFLIGHT_OK")):
            self.assertTrue(deploy.remote_dns_preflight(object()))

    def test_remote_dns_preflight_executes_fail_closed_state_matrix(self):
        cases = (
            (dict(db_present=True, phase="idle", unit="inactive", load="loaded"), True),
            (dict(db_present=True, phase="probing", unit="inactive", load="loaded"), False),
            (dict(db_present=True, row_present=False,
                  unit="inactive", load="loaded"), False),
            (dict(db_present=True, phase="", unit="inactive", load="loaded"), False),
            (dict(db_present=False, unit="inactive", load="not-found"), True),
            (dict(db_present=False, unit="inactive", load="loaded"), False),
            (dict(db_present=True, table_present=False, unit="inactive", load="not-found"), True),
            (dict(db_present=True, table_present=False, unit="inactive", load="loaded"), False),
            (dict(db_present=True, phase="idle", unit="active", load="loaded"), False),
            (dict(db_present=True, phase="idle", unit="activating", load="loaded"), False),
            (dict(db_present=True, phase="idle", unit="deactivating", load="loaded"), False),
        )
        for params, expected in cases:
            with self.subTest(params=params):
                ok, detail = self._run_remote_dns_program(**params)
                self.assertEqual(ok, expected, detail)

    def test_canonical_preflight_rejects_every_dangling_installed_artifact(self):
        def systemctl(command, **_kwargs):
            value = "inactive" if "is-active" in command else "not-found"
            return types.SimpleNamespace(stdout=value + "\n", stderr="", returncode=0)

        artifacts = (
            "/etc/vpn-panel/config.json",
            "/opt/vpn-panel/VERSION",
            "/var/lib/vpn-panel/state.db",
        )
        for dangling in artifacts:
            with self.subTest(dangling=dangling), \
                    mock.patch("os.path.lexists",
                               side_effect=lambda path, d=dangling: path == d), \
                    mock.patch("os.path.isfile", return_value=False), \
                    mock.patch("builtins.open", side_effect=FileNotFoundError(dangling)), \
                    mock.patch("subprocess.run", side_effect=systemctl):
                with self.assertRaises(SystemExit):
                    exec(deploy.REMOTE_DNS_PREFLIGHT_PROGRAM, {})

    def test_remote_dns_preflight_uses_custom_database_from_live_config(self):
        opened = []

        class Connection:
            def __init__(self, phase):
                self.phase = phase

            def execute(self, query, _params=()):
                if "sqlite_master" in query:
                    return types.SimpleNamespace(fetchone=lambda: (1,))
                return types.SimpleNamespace(fetchone=lambda: (self.phase,))

            def close(self):
                pass

        def connect(location, **_kwargs):
            opened.append(location)
            return Connection("probing" if "/custom/state.db" in location else "idle")

        def exists(path):
            return path == "/etc/vpn-panel/config.json"

        def systemctl(command, **_kwargs):
            value = "inactive" if "is-active" in command else "loaded"
            return types.SimpleNamespace(stdout=value + "\n", stderr="", returncode=0)

        with mock.patch("os.path.lexists", side_effect=exists), \
                mock.patch("os.path.isfile", return_value=True), \
                mock.patch("builtins.open",
                           return_value=io.StringIO('{"db":"/custom/state.db"}')), \
                mock.patch("sqlite3.connect", side_effect=connect), \
                mock.patch("subprocess.run", side_effect=systemctl):
            with self.assertRaisesRegex(SystemExit, "not idle"):
                exec(deploy.REMOTE_DNS_PREFLIGHT_PROGRAM, {})
        self.assertEqual(opened, ["file:/custom/state.db?mode=ro"])

    def test_remote_deploy_rejects_incompatible_base_contract(self):
        with mock.patch.object(deploy, "run_result", return_value=(1, "")):
            with self.assertRaisesRegex(SystemExit, "полный UPDATE=1 setup.sh"):
                deploy.require_remote_base_contract(object())
        with mock.patch.object(
                deploy, "run_result", return_value=(0, "REDUT_BASE_CONTRACT_OK")):
            self.assertTrue(deploy.require_remote_base_contract(object()))


if __name__ == "__main__":
    unittest.main()
