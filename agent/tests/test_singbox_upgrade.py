"""Core migration, old backup selection, and installer failure regressions."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

import _ctx
import apply as apply_mod
import dns_runtime
from singbox_config import migrate

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "install/templates/sing-box.config.json"


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.legacy = _ctx.fixture("singbox_config_reference.json")

    def test_upgrade_preserves_connections_telegram_and_tun(self):
        before = copy.deepcopy(self.legacy)
        result = migrate(self.legacy)
        self.assertEqual(self.legacy, before)
        self.assertEqual(result["outbounds"], before["outbounds"][:2])
        self.assertEqual(result["route"]["rules"][2:], before["route"]["rules"][1:])
        self.assertEqual(result["route"]["rules"][0],
                         {"inbound": "tun-in", "action": "sniff", "timeout": "500ms"})
        self.assertEqual(result["route"]["rules"][1],
                         {"protocol": "dns", "action": "hijack-dns"})
        self.assertEqual(result["inbounds"][0]["address"], before["inbounds"][0]["address"])
        self.assertFalse(result["inbounds"][0]["auto_route"])
        self.assertEqual(result["dns"]["servers"][0]["detour"], "socks-out")
        self.assertEqual(migrate(result), result)

    def test_http_mode_keeps_quic_rejection_after_dns(self):
        socks, http, quic = apply_mod.choose_outbounds("192.0.2.10", "u", "p", None, 8080)
        result = migrate(apply_mod.patch_config(self.legacy, socks, http, quic))
        repeated = apply_mod.patch_config(result, socks, http, quic)
        self.assertEqual(result, repeated)
        self.assertEqual(result["route"]["rules"][2]["action"], "reject")
        self.assertTrue(all(o["type"] == "http" for o in result["outbounds"]))

    def test_unknown_legacy_dns_is_rejected_without_dropping_settings(self):
        self.legacy["dns"]["servers"][0]["client_subnet"] = "192.0.2.1"
        with self.assertRaises(ValueError):
            migrate(self.legacy)

    def test_rollback_installer_combination_does_not_duplicate_sniff(self):
        mixed = copy.deepcopy(self.legacy)
        mixed["route"] = migrate(self.legacy)["route"]
        self.assertEqual(migrate(mixed), migrate(self.legacy))

    def test_new_template_contains_no_removed_options(self):
        template = json.loads(TEMPLATE.read_text())
        self.assertEqual(migrate(template), template)
        self.assertTrue(all(o["type"] != "dns" for o in template["outbounds"]))

    def test_rescue_uses_typed_doh_and_hijacks_entire_dns_listener(self):
        for transport in ("direct", "proxy"):
            cfg = dns_runtime.build_gateway_config(
                {"subnet": "10.8.0.0/24", "dns_rescue": {"listen_port": 5353}},
                {"endpoint": "https://1.1.1.1/resolve", "sni": "1.1.1.1",
                 "transport": transport}, self.legacy)
            self.assertEqual(cfg["dns"]["servers"][0]["type"], "https")
            self.assertEqual(cfg["dns"]["servers"][0]["path"], "/resolve")
            self.assertEqual(cfg["dns"]["servers"][0]["detour"], "rescue-" + transport)
            self.assertEqual(cfg["route"]["rules"],
                             [{"inbound": ["rescue-in"], "action": "hijack-dns"}])
            self.assertEqual(migrate(cfg), cfg)

    def test_old_backup_is_immutable_and_derived_target_is_repeatable(self):
        with tempfile.TemporaryDirectory() as tmp:
            ring = Path(tmp) / "ring"
            ring.mkdir()
            live = Path(tmp) / "live.json"
            backup = ring / "20260101-010101.json"
            live.write_text(json.dumps(migrate(self.legacy)))
            backup.write_text(json.dumps(self.legacy))
            original = backup.read_bytes()
            cfg = {"ring": str(ring), "singbox_config": str(live)}
            target = apply_mod.compatible_backup(cfg, str(backup))
            self.assertNotEqual(target, str(backup))
            self.assertEqual(backup.read_bytes(), original)
            self.assertEqual(json.loads(Path(target).read_text()), migrate(self.legacy))
            self.assertEqual(apply_mod.compatible_backup(cfg, str(backup)), target)
            self.assertEqual(Path(target).stat().st_mode & 0o777, 0o600)
            live.write_text(json.dumps(self.legacy))
            self.assertEqual(apply_mod.compatible_backup(cfg, str(backup)), str(backup))

    def test_panel_deploy_checks_core_before_any_payload_copy(self):
        spec = importlib.util.spec_from_file_location("core_setup_panel", ROOT / "install/setup_panel.py")
        installer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(installer)
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "sing-box"
            fake.write_bytes(b"old core")
            with self.assertRaisesRegex(SystemExit, "несовместимо"):
                installer.require_core(str(fake))
            installer.NETWORK_LOCK = str(Path(tmp) / "network.lock")
            for extra in ([], ["--no-panel"]):
                with mock.patch("sys.argv", ["setup_panel.py"] + extra), \
                        mock.patch.object(installer.os, "geteuid", create=True, return_value=0), \
                        mock.patch.object(installer, "require_core", side_effect=SystemExit("old core")), \
                        mock.patch.object(installer, "copy_files") as copy_files, \
                        mock.patch.object(installer.os, "makedirs") as makedirs:
                    with self.assertRaisesRegex(SystemExit, "old core"):
                        installer.main()
                    copy_files.assert_not_called()
                    makedirs.assert_not_called()


@unittest.skipUnless(shutil.which("bash"), "installer requires bash")
class InstallerCoreTests(unittest.TestCase):
    """Execute the real core sections in a fake filesystem with service doubles."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root / "usr/local/bin"
        self.etc = self.root / "etc/sing-box"
        self.bin.mkdir(parents=True)
        self.etc.mkdir(parents=True)
        self.legacy = _ctx.fixture("singbox_config_reference.json")
        self.live = self.etc / "config.json"
        self.live.write_text(json.dumps(self.legacy))
        self.live.chmod(0o600)
        self.old = b'#!/bin/sh\necho "sing-box version 1.11.7"\n'
        (self.bin / "sing-box").write_bytes(self.old)
        (self.bin / "sing-box").chmod(0o755)
        (self.bin / "vpn-boot-setup.sh").write_text("#!/bin/sh\nexit 0\n")
        self.new = (b'#!/bin/sh\nif [ "$1" = version ]; then echo "sing-box version 1.14.5"; '
                    b'else exit "${CORE_REJECT:-0}"; fi\n')
        staged = self.root / "sing-box-1.14.5-linux-amd64/sing-box"
        staged.parent.mkdir()
        staged.write_bytes(self.new)
        staged.chmod(0o755)
        self.archive = self.root / "archive.tgz"
        with tarfile.open(self.archive, "w:gz") as archive:
            archive.add(staged, arcname="sing-box-1.14.5-linux-amd64/sing-box")
        doubles = self.root / "doubles"
        doubles.mkdir()
        (doubles / "curl").write_text('#!/bin/bash\ncp "$CORE_ARCHIVE" "${@: -1}"\n')
        (doubles / "systemctl").write_text('#!/bin/sh\necho "$*" >> "$CORE_EVENTS"\nexit 0\n')
        for file in doubles.iterdir():
            file.chmod(0o755)
        install = (ROOT / "install/install.sh").read_text()
        section2 = install[install.index('# ── 2.'):install.index('# ── 3.')]
        section5 = install[install.index('# ── 5.'):install.index('# Действующий upstream')]
        self.script = ('#!/bin/bash\nset -uo pipefail\n'
                       'log(){ echo "$*"; }\ndie(){ echo "$*" >&2; exit 1; }\n'
                       + section2 + section5)
        self.script = self.script.replace('/usr/local/bin', str(self.bin)).replace(
            '/etc/sing-box', str(self.etc))
        self.script = self.script.replace(
            'ca57e405be6b7dc79a0efa91823a0cc4d81138cbe4a9aacbfd749c65e6fca3b2',
            hashlib.sha256(self.archive.read_bytes()).hexdigest()).replace(
            'c90cb751197910feabc43026491e451b8ed1800ef7d493d1e31cd32a0b6a4383',
            hashlib.sha256(self.new).hexdigest())
        self.env = dict(os.environ, PATH=str(doubles) + os.pathsep + os.environ['PATH'],
                        HERE=str(ROOT / "install"), TPL=str(TEMPLATE.parent),
                        CORE_ARCHIVE=str(self.archive), CORE_EVENTS=str(self.root / "events"),
                        SINGBOX_VERSION="1.14.5", UP_HOST="192.0.2.20", UP_USER="u",
                        UP_PASS="p", UP_SOCKS="1080", UP_HTTP="8080")

    def run_install(self, suffix="", **env):
        return subprocess.run(["bash"], input=self.script + suffix, env=dict(self.env, **env),
                              text=True, capture_output=True, timeout=15)

    def test_upgrade_and_repeat_preserve_selected_exit(self):
        for _ in range(2):
            result = self.run_install()
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(json.loads(self.live.read_text()), migrate(self.legacy))
            self.assertEqual((self.bin / "sing-box").read_bytes(), self.new)
            self.assertEqual(self.live.stat().st_mode & 0o777, 0o600)

    def test_fresh_install_and_forced_upstream(self):
        self.live.unlink()
        (self.bin / "sing-box").unlink()
        result = self.run_install()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(self.live.read_text())["outbounds"][0]["server"], "192.0.2.20")

    def test_config_check_failure_keeps_old_binary_and_config(self):
        before = self.live.read_bytes()
        result = self.run_install(CORE_REJECT="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.bin / "sing-box").read_bytes(), self.old)
        self.assertEqual(self.live.read_bytes(), before)
        self.assertFalse((self.root / "events").exists())

    def test_error_after_activation_restores_pair_and_service(self):
        before = self.live.read_bytes()
        result = self.run_install('\nexit 9\n')
        self.assertEqual(result.returncode, 9, result.stdout + result.stderr)
        self.assertEqual((self.bin / "sing-box").read_bytes(), self.old)
        self.assertEqual(self.live.read_bytes(), before)
        self.assertIn("restart sing-box", (self.root / "events").read_text())


if __name__ == "__main__":
    unittest.main()
