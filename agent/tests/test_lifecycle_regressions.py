"""Offline regressions for deployment result propagation and profile overrides."""
import contextlib
import io
import os
import re
import sys
import unittest
from unittest import mock

import _ctx  # noqa: F401
import deploy

sys.path.insert(0, os.path.join(os.path.dirname(deploy.PANEL_DIR), "install"))
import bootstrap  # noqa: E402
import profiles  # noqa: E402


class TestBootstrapResult(unittest.TestCase):
    def test_requested_panel_failure_is_not_green_base_only_success(self):
        connection = mock.Mock()
        profile = profiles.build_profile("node1", "192.0.2.10", "synthetic")
        net = {"wan": "eth0", "gw": "192.0.2.1", "server_ip": "192.0.2.10"}
        output = io.StringIO()
        with mock.patch.object(bootstrap, "connect", return_value=connection), \
                mock.patch.object(bootstrap, "build", return_value=profile), \
                mock.patch.object(bootstrap, "detect_net", return_value=net), \
                mock.patch.object(bootstrap, "remote_dns_preflight"), \
                mock.patch.object(bootstrap, "upload"), \
                mock.patch.object(bootstrap, "run_stream", return_value=(0, "")), \
                mock.patch.object(bootstrap, "fetch_clients", return_value=[]), \
                mock.patch.object(bootstrap, "deploy_panel", return_value=False), \
                mock.patch.object(bootstrap, "verify", return_value=([], [])) as verify, \
                mock.patch.object(bootstrap, "run", return_value=""), \
                contextlib.redirect_stdout(output):
            try:
                rc = bootstrap.main(["--host", "192.0.2.10", "--pw", "synthetic"])
            except SystemExit as error:
                rc = error.code
        self.assertNotEqual(rc, 0, "requested panel failure must fail bootstrap")
        self.assertNotIn("verify зелёный", output.getvalue())
        verify.assert_not_called()
        connection.close.assert_called_once()

    def test_final_verify_rejects_http_error_text_containing_ok(self):
        profile = profiles.build_profile("node1", "192.0.2.10", "synthetic")
        net = {"wan": "eth0", "gw": "192.0.2.1", "server_ip": "192.0.2.10"}

        def remote(_connection, command, **_kwargs):
            if "sing-box version" in command:
                return profile["singbox_version"]
            if "systemctl is-active" in command:
                return "active"
            if "table middleman" in command:
                return "default dev tun0"
            if "ip rule show" in command:
                return "1"
            if "api.ipify.org" in command:
                return profile["upstream"]["host"]
            if "wg show wg0 peers" in command:
                return "1"
            if "mangle -S PREROUTING" in command:
                return "-A PREROUTING -s %s -j REDUT_PREROUTING" % profile["subnet"]
            if "mangle -S REDUT_PREROUTING" in command:
                prefix = "-A REDUT_PREROUTING -s %s " % profile["subnet"]
                return (prefix + "-d 192.0.2.10/32 -j RETURN\n"
                        + prefix + "-d %s -j RETURN\n" % profile["subnet"]
                        + prefix + "-j MARK --set-xmark 0x64/0xffffffff")
            if "MASQUERADE" in command:
                return "1"
            if "CHANGE_ME" in command:
                return "0\nenv-ok"
            if "print('admin' in" in command:
                return "True"
            return ""

        with mock.patch.object(bootstrap, "run", side_effect=remote), \
                mock.patch.object(bootstrap, "run_result",
                                  return_value=(22, "HTTP 503: not ok")), \
                contextlib.redirect_stdout(io.StringIO()):
            problems, _warnings = bootstrap.verify(object(), profile, net, True)
        self.assertTrue(any("панель /healthz" in item for item in problems))
        self.assertEqual(len(problems), 1)


class TestDeployResult(unittest.TestCase):
    def _run_deploy(self, *, panel_failed=False, preflight_failed=False, panel_port=8443):
        connection = mock.MagicMock()
        lock = mock.Mock()
        commands = []
        timeline = []
        connection.open_sftp.return_value.put.side_effect = (
            lambda *_args, **_kwargs: timeline.append("upload"))

        def result(_connection, command, **_kwargs):
            commands.append(command)
            if "systemctl restart vpn-panel" in command:
                return (1, "failed") if panel_failed else (0, "active")
            if "/healthz" in command:
                return 0, "ok"
            if ".get('panel_port')" in command:
                timeline.append("panel-port")
                return 0, str(panel_port)
            if "REDUT_DNS_IDENTITY_OK" in command:
                return 0, "REDUT_DNS_IDENTITY_OK"
            if "enable --now redut-dns-rescue-watchdog.timer" in command:
                return 0, "active"
            if "cat /etc/vpn-panel/secrets.json" in command:
                return 0, '{"admin":{"pw":"synthetic"}}'
            if "panel.crt && echo yes" in command:
                return 0, "yes"
            if "print('admin' in" in command:
                return 0, "True"
            return 0, ""

        with mock.patch.dict(deploy.SERVERS, {"audit": {
                "host": "192.0.2.10", "pw": ["synthetic"], "config": {}}}), \
                mock.patch.object(deploy, "connect", return_value=connection), \
                mock.patch.object(deploy, "acquire_remote_network_lock", return_value=lock), \
                mock.patch.object(deploy, "remote_dns_preflight",
                                  side_effect=SystemExit("blocked") if preflight_failed else None), \
                mock.patch.object(deploy, "require_remote_base_contract"), \
                mock.patch.object(deploy, "run_result", side_effect=result), \
                contextlib.redirect_stdout(io.StringIO()):
            try:
                rc = deploy.main(["audit", "--with-panel", "--clean", "--keep-config"])
            except SystemExit as error:
                rc = error.code
        return rc, connection, lock, commands, timeline

    def test_panel_activation_failure_is_not_success(self):
        rc, connection, lock, _commands, _timeline = self._run_deploy(panel_failed=True)
        self.assertNotEqual(rc, 0)
        connection.close.assert_called_once()
        lock.close.assert_called_once()

    def test_preflight_failure_always_releases_ssh_and_network_lock(self):
        rc, connection, lock, _commands, _timeline = self._run_deploy(preflight_failed=True)
        self.assertNotEqual(rc, 0)
        connection.close.assert_called_once()
        lock.close.assert_called_once()

    def test_success_requires_panel_healthz(self):
        rc, connection, lock, commands, _timeline = self._run_deploy()
        self.assertEqual(rc, 0)
        self.assertTrue(any("/healthz" in command for command in commands))
        connection.close.assert_called_once()
        lock.close.assert_called_once()

    def test_keep_config_probes_actual_custom_port(self):
        rc, _connection, _lock, commands, timeline = self._run_deploy(panel_port=9443)
        self.assertEqual(rc, 0)
        self.assertTrue(any("127.0.0.1:9443/healthz" in command for command in commands))
        self.assertLess(timeline.index("panel-port"), timeline.index("upload"))

    def test_invalid_live_panel_port_fails_before_any_upload(self):
        rc, _connection, _lock, _commands, timeline = self._run_deploy(panel_port=70000)
        self.assertNotEqual(rc, 0)
        self.assertEqual(timeline, ["panel-port"])

    def test_active_process_without_healthy_endpoint_is_failure(self):
        with mock.patch.object(deploy, "run_result",
                               side_effect=[(0, "active"), (22, "HTTP 503")]):
            with self.assertRaisesRegex(SystemExit, "healthz"):
                deploy.activate_panel(object(), 8443, wait_s=0)


class TestProfileSubnetOverride(unittest.TestCase):
    def test_subnet_override_moves_server_and_default_client_together(self):
        original = profiles.PROFILES["node1"]["wg_ip"]
        result = profiles.build_profile("node1", "192.0.2.10", "synthetic",
                                        {"subnet": "10.20.0.0/24"})
        self.assertEqual(result["wg_ip"], "10.20.0.1")
        self.assertEqual(result["wg_addr"], "10.20.0.1/24")
        self.assertEqual(result["clients"][0]["addr"], "10.20.0.5")
        self.assertEqual(profiles.PROFILES["node1"]["wg_ip"], original)

    def test_explicit_addresses_win_over_profile_rebasing(self):
        clients = [{"name": "custom", "addr": "10.20.0.9"}]
        result = profiles.build_profile("node1", "192.0.2.10", "synthetic", {
            "subnet": "10.20.0.0/24", "wg_ip": "10.20.0.2", "clients": clients})
        self.assertEqual(result["wg_ip"], "10.20.0.2")
        self.assertEqual(result["clients"], clients)

    def test_smaller_subnet_rejects_client_that_does_not_fit(self):
        with self.assertRaisesRegex(ValueError, "client|клиент|адрес"):
            profiles.build_profile("node1", "192.0.2.10", "synthetic",
                                   {"subnet": "10.20.0.0/30"})

    def test_explicit_clients_respect_non_24_network_boundary(self):
        self.assertEqual(bootstrap.parse_clients("2", "10.20.0.128/25"), [
            {"name": "client1", "addr": "10.20.0.130"},
            {"name": "client2", "addr": "10.20.0.131"},
        ])

    def test_one_command_setup_uses_network_offsets_for_non_24_subnet(self):
        repo_root = os.path.dirname(deploy.PANEL_DIR)
        setup_path = os.path.join(repo_root, "install", "setup.sh")
        if not os.path.isfile(setup_path):
            setup_path = os.path.join(repo_root, "setup.sh")
        with open(setup_path, encoding="utf-8") as source:
            setup = source.read()
        block = re.search(
            r'python3 - "\$NAME" "\$SUBNET" "\$CLIENTS" <<\'PY\'[^\n]*\n(.*?)\nPY\nchmod 600',
            setup, re.DOTALL)
        self.assertIsNotNone(block, "setup.sh params heredoc not found")

        def command_result(command, **_kwargs):
            stdout = ("default via 192.0.2.1 dev eth0\n" if "route show default" in command
                      else "192.0.2.10\n")
            return mock.Mock(stdout=stdout)

        output = io.StringIO()
        with mock.patch.object(sys, "argv", ["setup-params", "node1",
                                              "10.20.0.128/25", "2"]), \
                mock.patch("subprocess.run", side_effect=command_result), \
                mock.patch.dict(os.environ, {"UPDATE": "0", "PROFILE": "node1"}), \
                contextlib.redirect_stdout(output):
            exec(compile(block.group(1), setup_path, "exec"), {"__name__": "__main__"})
        self.assertIn("CLIENTS='client1:10.20.0.130 client2:10.20.0.131'",
                      output.getvalue())

    def test_preserved_client_address_must_belong_to_active_subnet(self):
        with self.assertRaisesRegex(ValueError, "не помещается"):
            profiles.parse_clients("phone:10.20.0.5", "10.20.0.128/25")

    def test_update_may_preserve_an_empty_client_list(self):
        self.assertEqual(profiles.parse_clients("", "10.20.0.128/25", allow_empty=True), [])

    def test_duplicate_client_names_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "имя.*повторяется"):
            profiles.parse_clients("phone,phone", "10.20.0.0/24")

    def test_explicit_clients_reject_exhausted_subnet(self):
        with self.assertRaisesRegex(ValueError, "не помещается"):
            bootstrap.parse_clients("3", "10.20.0.0/30")

    def test_update_effective_wg_ip_uses_non_24_network_address(self):
        profile = profiles.PROFILES["node1"]
        self.assertEqual(
            profiles.effective_wg_ip(profile, "10.20.0.128/25"),
            "10.20.0.129")

    def test_update_effective_wg_ip_rejects_subnet_without_usable_host(self):
        with self.assertRaisesRegex(ValueError, "wg0"):
            profiles.effective_wg_ip(profiles.PROFILES["node1"], "10.20.0.0/31")


if __name__ == "__main__":
    unittest.main()
