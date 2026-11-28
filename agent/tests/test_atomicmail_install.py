"""Mail installation defaults and preservation, entirely offline."""
import ast
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

import _ctx  # noqa: F401

ROOT = Path(__file__).resolve().parents[2]
PANEL = ROOT / ("panel" if (ROOT / "panel").is_dir() else "agent")


def literal(path, name):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == name for target in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError(name)


class AtomicMailInstallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="redut-mail-install-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        env = mock.patch.dict(os.environ, {"VPN_PANEL_LOCK_DIR": str(self.root / "locks")})
        env.start(); self.addCleanup(env.stop)
        spec = importlib.util.spec_from_file_location(
            "mail_setup_panel", ROOT / "install/setup_panel.py")
        self.installer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.installer)
        for attr in ("OPT", "ETC", "VAR"):
            value = self.root / attr.lower()
            value.mkdir()
            setattr(self.installer, attr, str(value))
        self.installer.NETWORK_LOCK = str(self.root / "network.lock")
        shutil.copyfile(PANEL / "config_store.py", Path(self.installer.OPT) / "config_store.py")
        self.config = Path(self.installer.ETC) / "config.json"
        self.secrets = Path(self.installer.ETC) / "secrets.json"
        self.net = {"gw": "192.0.2.1", "wan": "eth-test", "server_ip": "192.0.2.10"}

    def write_config(self, transport=None):
        self.installer.write_config("mail-test", self.net, 8443, "10.77.0.0/24", 51820,
                                    True, transport)
        return json.loads(self.config.read_text())

    def test_new_install_defaults_to_atomicmail_and_explicit_smtp_overrides(self):
        self.assertEqual(self.write_config()["mail_transport"], "atomicmail")
        self.config.unlink()
        self.assertEqual(self.write_config("smtp")["mail_transport"], "smtp")

    def test_reinstall_preserves_both_explicit_transports(self):
        for mode in ("atomicmail", "smtp"):
            self.write_config(mode)
            self.assertEqual(self.write_config()["mail_transport"], mode)

    def test_legacy_smtp_config_is_not_silently_migrated(self):
        cfg = self.write_config("smtp")
        cfg.pop("mail_transport")
        self.config.write_text(json.dumps(cfg))
        existing = {"admin": {"pw": "synthetic-admin"},
                    "smtp": {"host": "smtp.example.test", "password": "your_smtp_password_here"}}
        self.secrets.write_text(json.dumps(existing))
        before = self.secrets.read_bytes()
        self.assertNotIn("mail_transport", self.write_config())
        self.assertFalse(self.installer.ensure_secrets())
        self.assertEqual(self.secrets.read_bytes(), before)
        with mock.patch.object(self.installer.importlib, "import_module") as load:
            self.assertFalse(self.installer.prepare_mail())
        load.assert_not_called()

    def test_reinstall_preserves_atomicmail_sender_and_recipient(self):
        self.write_config("atomicmail")
        existing = {"admin": {"pw": "synthetic-admin"},
                    "atomicmail": {"api_key": "your_atomic_api_key_here", "address": "sender@example.test"},
                    "mail": {"to": "owner@example.test"}}
        self.installer.atomic_json(str(self.secrets), existing)
        before = self.secrets.read_bytes()
        self.write_config()
        self.assertFalse(self.installer.ensure_secrets())
        self.assertEqual(self.secrets.read_bytes(), before)
        self.assertEqual(self.secrets.stat().st_mode & 0o777, 0o600)

    def test_preparation_checks_ready_and_does_not_print_provider_errors(self):
        self.write_config("atomicmail")
        self.installer.ensure_secrets()
        provider = mock.Mock()
        old_path = list(sys.path)
        for result in ({"ready": True}, {"ready": False}, RuntimeError("synthetic-secret-token")):
            provider.ensure_ready.reset_mock()
            provider.ensure_ready.side_effect = result if isinstance(result, Exception) else None
            provider.ensure_ready.return_value = result
            output = io.StringIO()
            with mock.patch.object(self.installer.importlib, "import_module", return_value=provider), \
                    contextlib.redirect_stdout(output):
                ready = self.installer.prepare_mail()
            self.assertEqual(ready, result == {"ready": True})
            provider.ensure_ready.assert_called_once_with(str(self.secrets))
            self.assertNotIn("synthetic-secret-token", output.getvalue())
            self.assertEqual(sys.path, old_path)

    def test_agent_only_payload_delivers_atomicmail_and_secret_writer(self):
        self.installer.copy_files(str(PANEL), with_panel=False)
        for name in ("atomicmail.py", "webpanel/__init__.py", "webpanel/auth.py"):
            self.assertTrue((Path(self.installer.OPT) / name).is_file(), name)
        self.assertFalse((Path(self.installer.OPT) / "webpanel/server.py").exists())
        deploy_files = literal(PANEL / "deploy.py", "AGENT_FILES") if (PANEL / "deploy.py").exists() else None
        if deploy_files is not None:
            self.assertEqual(deploy_files, self.installer.AGENT_FILES)

    def test_main_prepares_after_payload_and_secrets_and_continues_if_mail_not_ready(self):
        seen = []
        def prepare():
            self.assertTrue((Path(self.installer.OPT) / "atomicmail.py").is_file())
            self.assertEqual(self.secrets.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(self.config.read_text())["mail_transport"], "atomicmail")
            seen.append("prepare")
            return False
        with mock.patch.multiple(self.installer, require_core=lambda: None,
                                 detect_net=lambda: self.net, sh=lambda *args, **kwargs: "",
                                 prepare_mail=prepare, install_units=lambda panel: seen.append("units"),
                                 install_crons=lambda: seen.append("crons")), \
                mock.patch.object(self.installer.os, "geteuid", return_value=0), \
                mock.patch.object(sys, "argv", ["setup_panel.py", "--src", str(PANEL), "--no-panel"]):
            self.assertEqual(self.installer.main(), 0)
        self.assertEqual(seen, ["prepare", "units", "crons"])

    @unittest.skipUnless(shutil.which("bash"), "public installer uses Bash")
    def test_public_smtp_flag_forwards_only_explicit_selection(self):
        entry = ROOT / ("install/setup.sh" if PANEL.name == "panel" else "setup.sh")
        shell = entry.read_text()
        parser = shell[shell.index("MAIL_ARGS=()"):shell.index("# ── 0a. UPDATE=1")]
        script = ('set -euo pipefail\ndie(){ exit 2; }\n' + parser
                  + '\nprintf "%s\\n" "${MAIL_ARGS[@]}"\n')
        for arguments, expected in (([], []), (["--smtp"], ["--mail-transport", "smtp"])):
            result = subprocess.run(["bash", "-c", script, "setup.sh", *arguments],
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.split(), expected)
        invalid = subprocess.run(["bash", "-c", script, "setup.sh", "--unknown"],
                                 capture_output=True, text=True, timeout=5)
        self.assertNotEqual(invalid.returncode, 0)

    @unittest.skipUnless((PANEL / "deploy.py").exists(), "operator deploy is not in public package")
    def test_remote_preparation_uses_actual_transport_and_never_prints_exceptions(self):
        program = literal(PANEL / "deploy.py", "MAIL_PREPARE_PROGRAM")
        for mode, outcome, marker in (("smtp", {"ready": True}, "REDUT_MAIL_SKIPPED"),
                                      ("atomicmail", {"ready": True}, "REDUT_MAIL_READY"),
                                      ("atomicmail", {"ready": False}, "REDUT_MAIL_DEFERRED"),
                                      ("atomicmail", RuntimeError("synthetic-secret"), "REDUT_MAIL_DEFERRED")):
            provider = mock.Mock()
            provider.ensure_ready.return_value = outcome
            provider.ensure_ready.side_effect = outcome if isinstance(outcome, Exception) else None
            output = io.StringIO()
            with mock.patch.dict(sys.modules, {"atomicmail": provider}), \
                    mock.patch.object(sys, "path", list(sys.path)), \
                    mock.patch.object(sys, "argv", ["prepare", self.installer.OPT]), \
                    mock.patch("builtins.open", return_value=io.StringIO(json.dumps({"mail_transport": mode}))), \
                    contextlib.redirect_stdout(output):
                exec(compile(program, "<prepare-mail>", "exec"), {})
            self.assertEqual(output.getvalue().strip(), marker)
            if mode == "smtp":
                provider.ensure_ready.assert_not_called()
            else:
                provider.ensure_ready.assert_called_once_with("/etc/vpn-panel/secrets.json")

    @unittest.skipUnless((PANEL / "deploy.py").exists(), "operator deploy is not in public package")
    def test_operator_config_writer_keeps_selected_mail_transport(self):
        tree = ast.parse((PANEL / "deploy.py").read_text())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                        and n.name == "put_config_atomic")
        program = next(ast.literal_eval(n.value) for n in ast.walk(function)
                       if isinstance(n, ast.Assign) and any(
                           isinstance(t, ast.Name) and t.id == "program" for t in n.targets))
        self.write_config("atomicmail")
        incoming = self.config.with_name("incoming.json")
        incoming.write_text(json.dumps({"mail_transport": "smtp", "server": "changed"}))
        with mock.patch.object(sys, "path", list(sys.path)), mock.patch.object(
                sys, "argv", ["writer", self.installer.OPT, str(self.config), str(incoming),
                              json.dumps(["mail_transport"])]):
            exec(compile(program, "<config-writer>", "exec"), {})
        result = json.loads(self.config.read_text())
        self.assertEqual(result, {"mail_transport": "atomicmail", "server": "changed"})

    @unittest.skipUnless((PANEL / "deploy.py").exists(), "operator deploy is not in public package")
    def test_operator_secret_writer_keeps_mail_state_under_its_lock(self):
        program = literal(PANEL / "deploy.py", "SECRET_WRITER_PROGRAM")
        current = {"admin": {"pw": "old-admin"}, "atomicmail": {"api_key": "old-key"},
                   "mail": {"to": "old@example.test"}, "smtp": {"host": "old.smtp.test"}}
        incoming = {"admin": {"pw": "new-admin"}, "atomicmail": {"api_key": "new-key"},
                    "mail": {"to": "new@example.test"}, "smtp": {"host": "new.smtp.test"},
                    "provider": {"key": "new-provider"}}
        stage = self.secrets.with_name("secrets.json.deploy-test")
        for path, payload in ((self.secrets, current), (stage, incoming)):
            path.write_text(json.dumps(payload)); path.chmod(0o600)
        fstat, lstat = os.fstat, os.lstat
        def owned(result):
            return types.SimpleNamespace(st_mode=result.st_mode, st_uid=0, st_mtime=result.st_mtime)
        with mock.patch.object(sys, "argv", ["writer", str(self.secrets), str(stage), "1"]), \
                mock.patch.object(os, "fstat", side_effect=lambda fd: owned(fstat(fd))), \
                mock.patch.object(os, "lstat", side_effect=lambda path: owned(lstat(path))):
            exec(compile(program, "<secret-writer>", "exec"), {})
        updated = json.loads(self.secrets.read_text())
        self.assertEqual(updated, dict(current, provider=incoming["provider"]))
        self.assertEqual(self.secrets.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
