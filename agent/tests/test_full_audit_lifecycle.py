"""Offline regressions for audit A01/A14/A15 using synthetic node data."""
import contextlib
import io
import json
import pathlib
import sys
import tempfile
import types
import unittest
from unittest import mock

import _ctx  # noqa: F401
import deploy
import update

sys.path.insert(0, str(pathlib.Path(deploy.PANEL_DIR).parent / "install"))
import bootstrap  # noqa: E402


class TestDeployLocalPreflight(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="redut-deploy-inputs-")
        self.addCleanup(temporary.cleanup)
        self.root = pathlib.Path(temporary.name)
        self.panel = self.root / "panel"
        self.panel.mkdir()
        (self.panel / "webpanel").mkdir()
        for relative in ("agent.py", "webpanel/server.py"):
            (self.panel / relative).write_text("# synthetic\n", encoding="utf-8")
        self.templates = self.root / "install/templates"
        self.templates.mkdir(parents=True)
        for name in ("redut-dns-rescue.service", "redut-dns-rescue-watchdog.service",
                     "redut-dns-rescue-watchdog.timer"):
            (self.templates / name).write_text("[Unit]\n", encoding="utf-8")
        (self.root / "VERSION").write_text("1.13.5\n", encoding="utf-8")
        self.secret = self.panel / ".secrets.local.json"
        self.secret.write_text('{"proxy6":{"key":"SYNTHETIC-KEY"}}', encoding="utf-8")
        self.connection = mock.MagicMock()
        self.lock = mock.Mock()
        self.output = io.StringIO()
        self.writes = []
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(mock.patch.multiple(
            deploy, PANEL_DIR=str(self.panel), AGENT_FILES=["agent.py"],
            PANEL_FILES=["webpanel/server.py"]))
        stack.enter_context(mock.patch.dict(deploy.SERVERS, {"audit": {
            "host": "192.0.2.10", "pw": ["SYNTHETIC-SSH"], "config": {}}}, clear=True))
        self.connect = stack.enter_context(mock.patch.object(
            deploy, "connect", return_value=self.connection))
        stack.enter_context(mock.patch.object(
            deploy, "acquire_remote_network_lock", return_value=self.lock))
        self.dns_preflight = stack.enter_context(mock.patch.object(deploy, "remote_dns_preflight"))
        stack.enter_context(mock.patch.object(deploy, "require_remote_base_contract"))
        stack.enter_context(mock.patch.object(deploy, "run_result", side_effect=self._remote))
        self.config_write = stack.enter_context(mock.patch.object(deploy, "put_config_atomic"))
        stack.enter_context(mock.patch.object(deploy, "put_secret_atomic", side_effect=self._secret_write))
        stack.enter_context(mock.patch.object(
            deploy, "remote_panel_config_upgrade_barrier", return_value=contextlib.nullcontext()))
        stack.enter_context(contextlib.redirect_stdout(self.output))

    @staticmethod
    def _remote(_connection, command, **_kwargs):
        if "REDUT_DNS_IDENTITY_OK" in command:
            return 0, "REDUT_DNS_IDENTITY_OK"
        if "cat /etc/vpn-panel/secrets.json" in command:
            return 0, '{"admin":{"pw":"SYNTHETIC-EXISTING-ADMIN"}}'
        if ".get('panel_port')" in command:
            return 0, "9443"
        if "print('admin' in" in command:
            return 0, "True"
        if "panel.crt && echo yes" in command:
            return 0, "yes"
        if "/healthz" in command:
            return 0, "ok"
        if "systemctl" in command:
            return 0, "active"
        return 0, ""

    def _secret_write(self, _connection, _sftp, path, data, **kwargs):
        self.writes.append((path, json.loads(data), kwargs))

    def test_normal_deploy_completes_and_preserves_admin(self):
        self.assertEqual(deploy.main(["audit", "--with-panel"]), 0)
        self.assertEqual(self.writes, [("/etc/vpn-panel/secrets.json", {
            "proxy6": {"key": "SYNTHETIC-KEY"},
            "admin": {"pw": "SYNTHETIC-EXISTING-ADMIN"}}, {"preserve_admin": True})])
        self.config_write.assert_called_once()
        self.connection.close.assert_called_once()
        self.lock.close.assert_called_once()
        self.connection.open_sftp.return_value.close.assert_called_once()
        self.assertNotIn("SYNTHETIC-KEY", self.output.getvalue())

    def test_normal_keep_config_deploy_completes(self):
        self.assertEqual(deploy.main(["audit", "--with-panel", "--keep-config"]), 0)
        self.config_write.assert_not_called()
        self.assertEqual(len(self.writes), 1)

    def test_clean_deploy_does_not_require_or_seed_local_secrets(self):
        self.secret.unlink()
        self.assertEqual(deploy.main(["audit", "--with-panel", "--clean"]), 0)
        self.assertEqual(self.writes, [])

    def test_clean_deploy_ignores_invalid_unused_local_secrets(self):
        self.secret.write_text("not JSON", encoding="utf-8")
        self.assertEqual(deploy.main(["audit", "--with-panel", "--clean"]), 0)
        self.assertEqual(self.writes, [])

    def test_missing_optional_version_preserves_deploy_contract(self):
        (self.root / "VERSION").unlink()
        self.assertEqual(deploy.main(["audit", "--clean"]), 0)

    def test_normal_and_clean_dry_runs_never_connect(self):
        for options in ([], ["--clean"]):
            with self.subTest(options=options):
                self.assertEqual(deploy.main(["audit", "--with-panel", "--dry-run"] + options), 0)
        self.connect.assert_not_called()
        self.assertNotIn("SYNTHETIC-KEY", self.output.getvalue())

    def test_invalid_secret_json_is_rejected_before_ssh_without_printing_payload(self):
        for raw in ('{"SYNTHETIC-KEY":', '[]', 'null'):
            with self.subTest(raw=raw):
                self.secret.write_text(raw, encoding="utf-8")
                with self.assertRaises(SystemExit) as caught:
                    deploy.main(["audit", "--with-panel"])
                self.assertNotIn("SYNTHETIC-KEY", str(caught.exception))
        self.connect.assert_not_called()

    def test_invalid_secret_json_also_fails_dry_run(self):
        self.secret.write_text("[]", encoding="utf-8")
        with self.assertRaises(SystemExit):
            deploy.main(["audit", "--dry-run"])
        self.connect.assert_not_called()

    def test_missing_local_inputs_fail_before_ssh(self):
        for path in (self.secret, self.panel / "agent.py",
                     self.panel / "webpanel/server.py",
                     self.templates / "redut-dns-rescue-watchdog.timer"):
            with self.subTest(path=path.name):
                original = path.read_bytes()
                path.unlink()
                try:
                    with self.assertRaises(SystemExit):
                        deploy.main(["audit", "--with-panel"])
                    self.connect.assert_not_called()
                finally:
                    path.write_bytes(original)

    def test_remote_dns_preflight_still_blocks_before_uploads(self):
        self.dns_preflight.side_effect = SystemExit("pending generation")
        with self.assertRaises(SystemExit):
            deploy.main(["audit", "--with-panel"])
        self.connection.open_sftp.assert_not_called()
        self.config_write.assert_not_called()
        self.assertEqual(self.writes, [])

    def test_unreadable_existing_version_is_rejected_before_ssh(self):
        real_open = open
        version = (self.root / "VERSION").resolve()

        def source_open(path, *args, **kwargs):
            if pathlib.Path(path).resolve() == version:
                raise PermissionError("synthetic unreadable source")
            return real_open(path, *args, **kwargs)

        with mock.patch("builtins.open", side_effect=source_open):
            with self.assertRaises(SystemExit):
                deploy.main(["audit", "--clean"])
        self.connect.assert_not_called()

    def test_bootstrap_seed_secrets_uses_normal_deploy(self):
        profile = {"name": "audit", "host": "192.0.2.10", "root_pw": "SYNTHETIC-SSH",
                   "role": "vpn-audit", "subnet": "10.8.0.0/24", "wg_port": 51820,
                   "wg_ip": "10.8.0.1", "panel_port": 8443}
        net = {"gw": "192.0.2.1", "wan": "eth0", "server_ip": "192.0.2.10"}
        args = types.SimpleNamespace(seed_secrets=True, regen_cert=False)
        with mock.patch.object(bootstrap, "PANEL_DIR", str(self.panel)):
            self.assertTrue(bootstrap.deploy_panel(profile, net, args))
        self.assertEqual(len(self.writes), 1)


class TestBootstrapOwnedPrerouting(unittest.TestCase):
    def _verify(self, *, jump=True, mark_first=False, mark="0x64/0xffffffff", subnet="10.8.0.0/24"):
        profile = {"singbox_version": "1.11.7", "subnet": subnet,
                   "upstream": {"host": "198.51.100.20"}}
        net = {"server_ip": "192.0.2.10"}
        prefix = "-A REDUT_PREROUTING -s 10.8.0.0/24 "
        rules = [prefix + "-d 192.0.2.10/32 -j RETURN",
                 prefix + "-d 10.8.0.0/24 -j RETURN"]
        marking = prefix + "-j MARK --set-xmark " + mark
        rules.insert(0 if mark_first else len(rules), marking)

        def remote(_connection, command, **_kwargs):
            if "sing-box version" in command:
                return profile["singbox_version"]
            if "systemctl is-active" in command:
                return "active"
            if "table middleman" in command:
                return "default dev tun0"
            if "MASQUERADE" in command:
                return "1" if "-s 10.8.0.0/24 " in command else "0"
            if "ip rule show" in command or "wg show wg0 peers" in command:
                return "1"
            if "api.ipify.org" in command:
                return profile["upstream"]["host"]
            if command == "iptables -t mangle -S PREROUTING":
                return "-P PREROUTING ACCEPT\n" + (
                    "-A PREROUTING -s 10.8.0.0/24 -j REDUT_PREROUTING" if jump else "")
            if command == "iptables -t mangle -S REDUT_PREROUTING":
                return "-N REDUT_PREROUTING\n" + "\n".join(rules)
            if "CHANGE_ME" in command:
                return "0\nenv-ok"
            raise AssertionError(command)

        with mock.patch.object(bootstrap, "run", side_effect=remote), \
                contextlib.redirect_stdout(io.StringIO()):
            return bootstrap.verify(object(), profile, net, False)

    def test_modern_owned_chain_passes(self):
        self.assertEqual(self._verify(), ([], []))

    def test_accepted_host_bits_match_normalized_iptables_network(self):
        profile = bootstrap.profiles.build_profile("node1", "192.0.2.10", "SYNTHETIC",
                                                    {"subnet": "10.8.0.1/24"})
        self.assertEqual(self._verify(subnet=profile["subnet"]), ([], []))

    def test_missing_jump_fails_even_with_valid_owned_rules(self):
        problems, _ = self._verify(jump=False)
        self.assertTrue(problems)

    def test_mark_above_returns_fails(self):
        problems, _ = self._verify(mark_first=True)
        self.assertTrue(problems)

    def test_wrong_mark_fails(self):
        problems, _ = self._verify(mark="0x65/0xffffffff")
        self.assertTrue(problems)


class TestManualUpdateDNSRecovery(unittest.TestCase):
    BEFORE = {"phase": "idle", "dnsmasq": False, "rescue_unit": False,
              "rescue_unit_state": "inactive"}

    def _verify(self, before, after, cfg=None):
        with mock.patch.object(update, "_singbox_ok", return_value=(True, "")), \
                mock.patch.object(update, "_is_active", return_value=True), \
                mock.patch.object(update, "_dns_update_state", return_value=after), \
                mock.patch.object(update, "_panel_ok", return_value=True):
            return update._verify_once(cfg or {"has_dnsmasq": True}, {"units": {}, "dns": before})

    def test_dnsmasq_recovery_is_accepted(self):
        self.assertEqual(self._verify(self.BEFORE, {**self.BEFORE, "dnsmasq": True}), (True, ""))

    def test_dnsmasq_deterioration_or_persistent_failure_is_rejected(self):
        for was_active in (True, False):
            with self.subTest(was_active=was_active):
                ok, reason = self._verify({**self.BEFORE, "dnsmasq": was_active}, self.BEFORE)
                self.assertFalse(ok)
                self.assertIn("dnsmasq", reason)

    def test_rescue_state_changes_remain_rejected(self):
        after = {**self.BEFORE, "dnsmasq": True}
        for mutation in ({"phase": "active"}, {"rescue_unit": True},
                         {"rescue_unit_state": "failed"}, {"generation": 2}):
            with self.subTest(mutation=mutation):
                self.assertFalse(self._verify(self.BEFORE, {**after, **mutation})[0])

    def test_automatic_updates_still_reject_unhealthy_dnsmasq(self):
        baseline = {"units": {"sing-box": True, "vpn-panel": True},
                    "panel": True, "dns": self.BEFORE}
        self.assertFalse(update.hard_ok(baseline))

    def test_manual_repair_finishes_after_one_setup_without_rollback(self):
        for force in (False, True):
            with self.subTest(force=force), tempfile.TemporaryDirectory(prefix="redut-repair-") as temporary:
                root = pathlib.Path(temporary)
                source, candidate, previous = (root / name for name in ("source", "candidate", "previous"))
                current = "1.13.5" if force else "1.13.4"
                for directory, version in ((source, current), (candidate, "1.13.5")):
                    directory.mkdir()
                    (directory / "install").mkdir()
                    (directory / "install/install.sh").write_text("# synthetic\n", encoding="utf-8")
                    (directory / "setup.sh").write_text("# UPDATE\n", encoding="utf-8")
                    (directory / "VERSION").write_text(version, encoding="utf-8")
                cfg = {"has_dnsmasq": True, "db": str(root / "state.db")}
                result = {"ok": False, "from": current, "to": "1.13.5", "rolled_back": False, "why": ""}
                baseline = {"units": {}, "dns": self.BEFORE}
                with mock.patch.multiple(update, REDUT_SRC=str(source), REDUT_NEW=str(candidate),
                                         REDUT_PREV=str(previous)), \
                        mock.patch.object(update, "status_write"), \
                        mock.patch.object(update, "_run_setup", return_value=(0, "")) as setup, \
                        mock.patch.object(update, "_cancel_boot_setup_before_rollback", return_value=True) as rollback, \
                        mock.patch.object(update, "verify_health", side_effect=update._verify_once), \
                        mock.patch.object(update, "_singbox_ok", return_value=(True, "")), \
                        mock.patch.object(update, "_is_active", return_value=True), \
                        mock.patch.object(update, "_dns_update_state", return_value={**self.BEFORE, "dnsmasq": True}), \
                        mock.patch.object(update, "_panel_ok", return_value=True):
                    actual = update._apply_install(cfg, None, None, lambda _message: None,
                                                   "1.13.5", True, result, baseline, force)
                self.assertTrue(actual["ok"], actual["why"])
                self.assertFalse(actual["rolled_back"])
                setup.assert_called_once()
                rollback.assert_not_called()
                self.assertEqual(update.node_version([str(source / "VERSION")]), "1.13.5")
                self.assertEqual(update.node_version([str(previous / "VERSION")]), current)


if __name__ == "__main__":
    unittest.main()
