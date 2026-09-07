# -*- coding: utf-8 -*-
import json
import os
import stat
import sys
import unittest
from types import SimpleNamespace
from unittest import mock


HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import dns_runtime


def config():
    return {
        "subnet": "10.77.0.0/24",
        "wan": "eth0",
        "gw": "192.0.2.1",
        "dns_rescue": {
            "listen_ip": "",
            "listen_port": 1053,
            "qps_per_peer": 50,
            "qps_burst_per_peer": 100,
            "tcp_connections_per_peer": 8,
            "canary_runner_sha256": "a" * 64,
            "canary_qname_suffix": "canary.redut.example",
            "canary_expected_ipv4": "192.0.2.53",
        },
    }


def runner_report(command, ok=True, challenge_override=None):
    challenge = command[command.index("--challenge") + 1]
    generation = command[command.index("--route-generation") + 1]
    qname = command[command.index("--qname") + 1]
    expected = command[command.index("--expected-ipv4") + 1]
    profiles = command[command.index("--profiles") + 1].split(",")
    dns_item = {"ok": ok, "qname": qname,
                "answer_ipv4": expected if ok else None,
                "ttl": 30 if ok else None}
    evidence = {}
    for profile in profiles:
        evidence[profile] = {
            "dns": {"udp": dict(dns_item), "tcp": dict(dns_item)},
            "application_dns": dict(dns_item),
            "controls": [{"id": "a", "ip_tls": True, "hostname": True},
                         {"id": "b", "ip_tls": True, "hostname": True}],
        }
    return SimpleNamespace(returncode=0, stdout=json.dumps({
        "version": 3, "challenge": challenge_override or challenge,
        "route_generation": generation,
        "query": {"qname": qname, "type": "A", "expected_ipv4": expected},
        "profiles": evidence}))


class FakeFirewall:
    """Small exact-rule iptables model with injectable command failures."""

    def __init__(self):
        self.chains = {
            ("nat", "PREROUTING"): [],
            ("filter", "INPUT"): [],
        }
        self.commands = []
        self.fail_delete = set()
        self.fail_delete_chain = set()

    def _referenced(self, table, target):
        for (rule_table, _chain), rules in self.chains.items():
            if rule_table != table:
                continue
            for rule in rules:
                if "-j" in rule and rule[rule.index("-j") + 1] == target:
                    return True
        return False

    def __call__(self, command, **_kwargs):
        command = list(command)
        self.commands.append(command)
        if command[0] == dns_runtime.CONNTRACK:
            return (1, "0 flow entries have been deleted")
        if command[0] != dns_runtime.IPTABLES or command[1:3] != ["-t", command[2]]:
            return (2, "unexpected command")
        table, action, chain = command[2], command[3], command[4]
        key = (table, chain)
        rule = tuple(command[5:])
        if action == "-S":
            if key not in self.chains:
                return (1, "missing")
            lines = ["-A %s %s" % (chain, " ".join(item))
                     for item in self.chains[key]]
            return (0, "\n".join(lines))
        if action == "-N":
            if key in self.chains:
                return (1, "exists")
            self.chains[key] = []
            return (0, "")
        if action == "-F":
            if key not in self.chains:
                return (1, "missing")
            self.chains[key] = []
            return (0, "")
        if action == "-X":
            if key in self.fail_delete_chain:
                return (2, "injected delete-chain failure")
            if key not in self.chains:
                return (1, "missing")
            if self._referenced(table, chain):
                return (1, "referenced")
            del self.chains[key]
            return (0, "")
        if action in ("-A", "-I"):
            if key not in self.chains:
                return (1, "missing")
            if action == "-I":
                self.chains[key].insert(0, rule)
            else:
                self.chains[key].append(rule)
            return (0, "")
        if action == "-C":
            return (0, "") if key in self.chains and rule in self.chains[key] else (1, "missing")
        if action == "-D":
            if (table, chain, rule) in self.fail_delete:
                return (2, "injected delete failure")
            if key not in self.chains or rule not in self.chains[key]:
                return (1, "missing")
            self.chains[key].remove(rule)
            return (0, "")
        return (2, "unsupported")


class TestFirewallFailOpen(unittest.TestCase):
    def setUp(self):
        self.cfg = config()
        self.firewall = FakeFirewall()

    def _activate(self, scope="all"):
        with mock.patch.object(dns_runtime.apply_mod, "run_cmd", side_effect=self.firewall):
            self.assertTrue(dns_runtime.activate_firewall(self.cfg, scope=scope))

    def test_activation_adds_scoped_input_acl_without_flushing_builtins(self):
        self._activate(scope="peer:10.77.0.9")
        input_rules = self.firewall.chains[("filter", dns_runtime.SCOPED_INPUT_CHAIN)]
        self.assertIn(tuple(dns_runtime._input_allow(
            self.cfg, "peer:10.77.0.9", "udp")), input_rules)
        self.assertIn(tuple(dns_runtime._listener_udp_rate_limit(
            self.cfg, "peer:10.77.0.9")), input_rules)
        self.assertIn(tuple(dns_runtime._listener_tcp_packet_rate_limit(
            self.cfg, "peer:10.77.0.9")), input_rules)
        self.assertIn(tuple(dns_runtime._tcp_connection_limit(
            self.cfg, "peer:10.77.0.9")), input_rules)
        self.assertIn(("-j", "DROP"), input_rules)
        self.assertTrue(any(rule[:2] == ("-i", "lo") for rule in input_rules))
        self.assertFalse(any(command[3:5] in (["-F", "INPUT"], ["-F", "PREROUTING"])
                             for command in self.firewall.commands))
        with mock.patch.object(dns_runtime.apply_mod, "run_cmd", side_effect=self.firewall):
            self.assertTrue(dns_runtime.firewall_effective(
                self.cfg, scope="peer:10.77.0.9"))

    def test_hashlimit_names_fit_linux_kernel_limit(self):
        for scope in ("all", "peer:10.77.0.9"):
            rules = [dns_runtime._listener_udp_rate_limit(self.cfg, scope),
                     dns_runtime._listener_tcp_packet_rate_limit(self.cfg, scope)]
            rules.extend(dns_runtime._query_rate_limit(
                self.cfg, scope, protocol) for protocol in dns_runtime._PROTOCOLS)
            for rule in rules:
                name = rule[rule.index("--hashlimit-name") + 1]
                self.assertLessEqual(len(name.encode("ascii")), 15)

    def test_redirect_cleanup_drains_full_subnet_after_any_owned_scope(self):
        self._activate(scope="peer:10.77.0.9")
        with mock.patch.object(dns_runtime.apply_mod, "run_cmd",
                               side_effect=self.firewall), \
             mock.patch.object(dns_runtime, "_drain_dns_conntrack") as drain:
            self.assertTrue(dns_runtime.deactivate_redirect(
                self.cfg, scope="peer:10.77.0.9"))
        drain.assert_called_once_with(self.cfg, "all", None)

    def test_successful_deactivation_proves_every_owned_artifact_absent(self):
        self._activate()
        with mock.patch.object(dns_runtime.apply_mod, "run_cmd", side_effect=self.firewall):
            self.assertTrue(dns_runtime.deactivate_firewall(self.cfg))
            self.assertTrue(dns_runtime.firewall_detached(self.cfg))
        self.assertNotIn(("nat", dns_runtime.CHAIN), self.firewall.chains)
        self.assertNotIn(("filter", dns_runtime.INPUT_CHAIN), self.firewall.chains)

    def test_tcp_jump_delete_failure_never_claims_success(self):
        self._activate()
        tcp_jump = tuple(dns_runtime._jump(
            "nat", "PREROUTING", "tcp", dns_runtime.CHAIN, self.cfg))
        self.firewall.fail_delete.add(("nat", "PREROUTING", tcp_jump))
        with mock.patch.object(dns_runtime.apply_mod, "run_cmd", side_effect=self.firewall):
            with self.assertRaises(dns_runtime.DNSRuntimeError):
                dns_runtime.deactivate_firewall(self.cfg)
            self.assertFalse(dns_runtime.firewall_detached(self.cfg))
        # Even though strict cleanup failed, the owned NAT chain was neutralized:
        # a residual jump cannot redirect traffic to a stopped listener.
        self.assertEqual(self.firewall.chains[("nat", dns_runtime.CHAIN)], [])
        self.assertIn(tcp_jump, self.firewall.chains[("nat", "PREROUTING")])

    def test_owned_chain_delete_failure_is_reported(self):
        self._activate()
        self.firewall.fail_delete_chain.add(("nat", dns_runtime.CHAIN))
        with mock.patch.object(dns_runtime.apply_mod, "run_cmd", side_effect=self.firewall):
            with self.assertRaises(dns_runtime.DNSRuntimeError):
                dns_runtime.deactivate_firewall(self.cfg)
            self.assertFalse(dns_runtime.firewall_detached(self.cfg))

    def test_inspection_error_is_never_reported_as_detached(self):
        with mock.patch.object(dns_runtime.apply_mod, "run_cmd", return_value=(2, "denied")):
            self.assertFalse(dns_runtime.firewall_detached(self.cfg))
            self.assertTrue(dns_runtime.firewall_attached(self.cfg))

    def test_partial_owned_artifact_is_visible_to_reconcile(self):
        self.firewall.chains[("nat", dns_runtime.CHAIN)] = []
        with mock.patch.object(dns_runtime.apply_mod, "run_cmd", side_effect=self.firewall):
            self.assertTrue(dns_runtime.firewall_attached(self.cfg))
            self.assertFalse(dns_runtime.firewall_detached(self.cfg))

    def test_scoped_and_global_use_distinct_owned_chains(self):
        self._activate(scope="peer:10.77.0.9")
        self.assertIn(("nat", dns_runtime.SCOPED_CHAIN), self.firewall.chains)
        self.assertNotIn(("nat", dns_runtime.GLOBAL_CHAIN), self.firewall.chains)
        with mock.patch.object(dns_runtime.apply_mod, "run_cmd", side_effect=self.firewall):
            self.assertTrue(dns_runtime.deactivate_firewall(self.cfg,
                                                            scope="peer:10.77.0.9"))
        self._activate(scope="all")
        self.assertIn(("nat", dns_runtime.GLOBAL_CHAIN), self.firewall.chains)
        self.assertNotIn(("nat", dns_runtime.SCOPED_CHAIN), self.firewall.chains)

    def test_scoped_effective_rejects_residual_global_pair(self):
        self._activate(scope="peer:10.77.0.9")
        self.firewall.chains[("nat", dns_runtime.GLOBAL_CHAIN)] = []
        self.firewall.chains[("filter", dns_runtime.GLOBAL_INPUT_CHAIN)] = []
        with mock.patch.object(dns_runtime.apply_mod, "run_cmd",
                               side_effect=self.firewall):
            self.assertFalse(dns_runtime.firewall_effective(
                self.cfg, scope="peer:10.77.0.9"))

    def test_global_effective_rejects_residual_scoped_pair(self):
        self._activate(scope="all")
        self.firewall.chains[("nat", dns_runtime.SCOPED_CHAIN)] = []
        self.firewall.chains[("filter", dns_runtime.SCOPED_INPUT_CHAIN)] = []
        with mock.patch.object(dns_runtime.apply_mod, "run_cmd",
                               side_effect=self.firewall):
            self.assertFalse(dns_runtime.firewall_effective(
                self.cfg, scope="all"))

    def test_listener_guard_rejects_simultaneous_broader_acl(self):
        with mock.patch.object(dns_runtime.apply_mod, "run_cmd",
                               side_effect=self.firewall):
            self.assertTrue(dns_runtime.stage_listener_acl(
                self.cfg, scope="peer:10.77.0.9"))
        self.firewall.chains[("filter", dns_runtime.GLOBAL_INPUT_CHAIN)] = []
        for protocol in dns_runtime._PROTOCOLS:
            self.firewall.chains[("filter", "INPUT")].append(tuple(
                dns_runtime._jump("filter", "INPUT", protocol,
                                  dns_runtime.GLOBAL_INPUT_CHAIN, self.cfg)))
        with mock.patch.object(dns_runtime.apply_mod, "run_cmd",
                               side_effect=self.firewall):
            self.assertFalse(dns_runtime.listener_guard_effective(
                self.cfg, scope="peer:10.77.0.9"))

    def test_acl_rebuild_installs_parent_drop_before_flushing_live_chain(self):
        with mock.patch.object(dns_runtime.apply_mod, "run_cmd",
                               side_effect=self.firewall):
            self.assertTrue(dns_runtime.stage_listener_acl(
                self.cfg, scope="peer:10.77.0.9"))
        observed = []

        def guarded(command, **kwargs):
            if command[:5] == [dns_runtime.IPTABLES, "-t", "filter", "-F",
                               dns_runtime.SCOPED_INPUT_CHAIN]:
                present = all(tuple(dns_runtime._listener_staging_drop(
                    self.cfg, protocol)) in self.firewall.chains[("filter", "INPUT")]
                              for protocol in dns_runtime._PROTOCOLS)
                observed.append(present)
            return self.firewall(command, **kwargs)

        with mock.patch.object(dns_runtime.apply_mod, "run_cmd", side_effect=guarded):
            self.assertTrue(dns_runtime.stage_listener_acl(
                self.cfg, scope="peer:10.77.0.9"))
        self.assertEqual(observed, [True])
        self.assertFalse(any(tuple(dns_runtime._listener_staging_drop(
            self.cfg, protocol)) in self.firewall.chains[("filter", "INPUT")]
                             for protocol in dns_runtime._PROTOCOLS))

    def test_failed_live_acl_rebuild_leaves_high_port_parent_guard(self):
        with mock.patch.object(dns_runtime.apply_mod, "run_cmd",
                               side_effect=self.firewall):
            self.assertTrue(dns_runtime.stage_listener_acl(
                self.cfg, scope="peer:10.77.0.9"))
        failed = False

        def inject(command, **kwargs):
            nonlocal failed
            if (not failed and command[:5] == [dns_runtime.IPTABLES, "-t", "filter",
                                               "-A", dns_runtime.SCOPED_INPUT_CHAIN]):
                failed = True
                return (2, "injected append failure")
            return self.firewall(command, **kwargs)

        with mock.patch.object(dns_runtime.apply_mod, "run_cmd", side_effect=inject):
            with self.assertRaises(dns_runtime.DNSRuntimeError):
                dns_runtime.stage_listener_acl(
                    self.cfg, scope="peer:10.77.0.9")
        for protocol in dns_runtime._PROTOCOLS:
            self.assertIn(tuple(dns_runtime._listener_staging_drop(
                self.cfg, protocol)), self.firewall.chains[("filter", "INPUT")])

    def test_upgrade_cleanup_removes_legacy_1130_chains(self):
        legacy_nat = dns_runtime.LEGACY_CHAIN
        legacy_input = dns_runtime.LEGACY_INPUT_CHAIN
        self.firewall.chains[("nat", legacy_nat)] = []
        self.firewall.chains[("filter", legacy_input)] = []
        for protocol in dns_runtime._PROTOCOLS:
            self.firewall.chains[("nat", "PREROUTING")].append(tuple(
                dns_runtime._jump("nat", "PREROUTING", protocol, legacy_nat, self.cfg)))
            self.firewall.chains[("filter", "INPUT")].append(tuple(
                dns_runtime._jump("filter", "INPUT", protocol, legacy_input, self.cfg)))
        with mock.patch.object(dns_runtime.apply_mod, "run_cmd", side_effect=self.firewall):
            self.assertTrue(dns_runtime.firewall_attached(self.cfg))
            self.assertTrue(dns_runtime.deactivate_firewall(self.cfg))
            self.assertTrue(dns_runtime.firewall_detached(self.cfg))


class TestRuntimeProofs(unittest.TestCase):
    def setUp(self):
        self.cfg = config()

    def test_service_start_requires_effective_active_state(self):
        with mock.patch.object(dns_runtime.apply_mod, "run_cmd",
                               side_effect=[(0, ""), (3, "inactive")]):
            with self.assertRaises(dns_runtime.DNSRuntimeError):
                dns_runtime.service_start()
        with mock.patch.object(dns_runtime.apply_mod, "run_cmd",
                               side_effect=[(0, ""), (0, "active")]):
            self.assertTrue(dns_runtime.service_start())

    def test_service_stop_requires_effective_inactive_state(self):
        with mock.patch.object(dns_runtime.apply_mod, "run_cmd",
                               side_effect=[(0, ""), (0, "active")]):
            with self.assertRaises(dns_runtime.DNSRuntimeError):
                dns_runtime.service_stop()
        with mock.patch.object(dns_runtime.apply_mod, "run_cmd",
                               side_effect=[(0, ""), (3, "inactive")]):
            self.assertTrue(dns_runtime.service_stop())

    def test_service_state_inspection_error_is_not_treated_as_stopped(self):
        with mock.patch.object(dns_runtime.apply_mod, "run_cmd",
                               side_effect=[(0, ""), (1, "permission denied")]):
            with self.assertRaises(dns_runtime.DNSRuntimeError):
                dns_runtime.service_stop()
        with mock.patch.object(dns_runtime.apply_mod, "run_cmd",
                               return_value=(1, "permission denied")):
            self.assertFalse(dns_runtime.service_inactive())

    @staticmethod
    def _wg_commands(allowed_ips, link_up=True):
        def run(command, *_args, **_kwargs):
            if command[0] == dns_runtime.IP:
                flags = "POINTOPOINT,NOARP,UP,LOWER_UP" if link_up else "POINTOPOINT,NOARP"
                return (0, "2: wg0: <%s> mtu 1420 state UNKNOWN" % flags)
            if command[0] == dns_runtime.WG:
                return (0, allowed_ips)
            return (2, "unexpected")
        return run

    def test_wireguard_scope_requires_unique_exact_peer_32(self):
        exact = "key-a\t10.77.0.9/32\nkey-b\t10.77.0.10/32\n"
        with mock.patch.object(dns_runtime.apply_mod, "run_cmd",
                               side_effect=self._wg_commands(exact)):
            self.assertTrue(dns_runtime.wireguard_scope_ready(
                self.cfg, "peer:10.77.0.9"))
            self.assertTrue(dns_runtime.wireguard_scope_ready(self.cfg, "all"))
        duplicate = "key-a\t10.77.0.9/32\nkey-b\t10.77.0.9/32\n"
        with mock.patch.object(dns_runtime.apply_mod, "run_cmd",
                               side_effect=self._wg_commands(duplicate)):
            self.assertFalse(dns_runtime.wireguard_scope_ready(
                self.cfg, "peer:10.77.0.9"))
        broad = "key-a\t10.77.0.0/24\n"
        with mock.patch.object(dns_runtime.apply_mod, "run_cmd",
                               side_effect=self._wg_commands(broad)):
            self.assertFalse(dns_runtime.wireguard_scope_ready(self.cfg, "all"))
        with mock.patch.object(dns_runtime.apply_mod, "run_cmd",
                               side_effect=self._wg_commands(exact, link_up=False)):
            self.assertFalse(dns_runtime.wireguard_scope_ready(self.cfg, "all"))

    def test_wireguard_identity_distinguishes_unknown_from_invalid(self):
        with mock.patch.object(dns_runtime, "_cmd", return_value=(1, "timeout")):
            self.assertEqual(dns_runtime.wireguard_scope_identity_state(
                self.cfg, "all")["status"], "unknown")
        duplicate = "key-a\t10.77.0.9/32\nkey-b\t10.77.0.9/32\n"
        with mock.patch.object(dns_runtime, "_cmd",
                               side_effect=self._wg_commands(duplicate)):
            self.assertEqual(dns_runtime.wireguard_scope_identity_state(
                self.cfg, "all")["status"], "invalid")
        exact = "key-a\t10.77.0.9/32\nkey-b\t10.77.0.10/32\n"
        with mock.patch.object(dns_runtime, "_cmd",
                               side_effect=self._wg_commands(exact)):
            result = dns_runtime.wireguard_scope_identity_state(self.cfg, "all")
        self.assertEqual(result["status"], "valid")
        self.assertTrue(result["identity"])

    def test_emergency_route_must_exactly_match_wan_and_gateway(self):
        good = "default via 192.0.2.1 dev eth0 proto static\n"
        with mock.patch.object(dns_runtime.apply_mod, "run_cmd", return_value=(0, good)):
            self.assertTrue(dns_runtime.emergency_route_ready(self.cfg))
        wrong = "default via 192.0.2.2 dev eth0\n"
        with mock.patch.object(dns_runtime.apply_mod, "run_cmd", return_value=(0, wrong)):
            self.assertFalse(dns_runtime.emergency_route_ready(self.cfg))
        duplicate = good + "default via 192.0.2.1 dev eth0 metric 10\n"
        with mock.patch.object(dns_runtime.apply_mod, "run_cmd", return_value=(0, duplicate)):
            self.assertFalse(dns_runtime.emergency_route_ready(self.cfg))

    def test_emergency_route_distinguishes_unknown_from_mismatch(self):
        with mock.patch.object(dns_runtime, "_cmd", return_value=(1, "timeout")):
            self.assertEqual(dns_runtime.emergency_route_state(self.cfg), "unknown")
        with mock.patch.object(dns_runtime, "_cmd", return_value=(0, "")):
            self.assertEqual(dns_runtime.emergency_route_state(self.cfg), "mismatch")
        multipath = ("default nexthop via 192.0.2.1 dev eth0 "
                     "nexthop via 192.0.2.2 dev eth1\n")
        with mock.patch.object(dns_runtime, "_cmd", return_value=(0, multipath)):
            self.assertEqual(dns_runtime.emergency_route_state(self.cfg), "mismatch")

    def test_preflight_controller_rejects_existing_symlink_like_root(self):
        group = SimpleNamespace(gr_gid=991)
        with mock.patch.object(dns_runtime.os, "name", "posix"), \
             mock.patch.object(
                 dns_runtime, "grp",
                 SimpleNamespace(getgrnam=mock.Mock(return_value=group))), \
             mock.patch.object(dns_runtime.os, "mkdir",
                               side_effect=FileExistsError()), \
             mock.patch.object(dns_runtime.os, "open",
                               side_effect=OSError("nofollow")):
            with self.assertRaises(dns_runtime.DNSRuntimeError):
                dns_runtime._ensure_preflight_controller_paths()
        self.assertNotEqual(os.path.dirname(dns_runtime.PREFLIGHT_CONFIG_PATH),
                            "/run/redut-dns-rescue")

    def test_client_path_requires_new_redirect_counter_hit(self):
        with mock.patch.object(dns_runtime, "_firewall_attached_strict", return_value=True), \
                mock.patch.object(dns_runtime, "_redirect_counters", side_effect=[
                    {"udp": 4, "tcp": 2}, {"udp": 5, "tcp": 2}]):
            self.assertTrue(dns_runtime.client_path_observed(self.cfg, "all", 0))
        with mock.patch.object(dns_runtime, "_firewall_attached_strict", return_value=True), \
                mock.patch.object(dns_runtime, "_redirect_counters", side_effect=[
                    {"udp": 4, "tcp": 2}, {"udp": 4, "tcp": 2}]):
            self.assertFalse(dns_runtime.client_path_observed(self.cfg, "all", 0))

    def test_counter_parser_requires_both_scoped_redirect_rules(self):
        saved = ("[7:560] -A REDUT_DNS_RESCUE_GLOBAL -s 10.77.0.0/24 -p udp -m udp "
                 "--dport 53 -j REDIRECT --to-ports 1053\n"
                 "[3:240] -A REDUT_DNS_RESCUE_GLOBAL -s 10.77.0.0/24 -p tcp -m tcp "
                 "--dport 53 -j REDIRECT --to-ports 1053\n")
        with mock.patch.object(dns_runtime.apply_mod, "run_cmd", return_value=(0, saved)):
            self.assertEqual(dns_runtime._redirect_counters(self.cfg, "all"),
                             {"udp": 7, "tcp": 3})
        with mock.patch.object(dns_runtime.apply_mod, "run_cmd",
                               return_value=(0, saved.splitlines()[0])):
            with self.assertRaises(dns_runtime.DNSRuntimeError):
                dns_runtime._redirect_counters(self.cfg, "all")

    def test_conntrack_drain_is_dns_only_and_scope_bounded(self):
        commands = []

        def run(command, timeout=40):
            commands.append(command)
            return (1, "0 flow entries have been deleted")

        with mock.patch.object(dns_runtime.apply_mod, "run_cmd", side_effect=run):
            dns_runtime._drain_dns_conntrack(
                self.cfg, "peer:10.77.0.9", deadline_monotonic=999999999.0)
        self.assertEqual(len(commands), 2)
        for command in commands:
            self.assertEqual(command[0], dns_runtime.CONNTRACK)
            self.assertIn("10.77.0.9/32", command)
            self.assertIn("--dport", command)
            self.assertIn("53", command)
            self.assertNotIn("-F", command)

    def test_external_runner_correlates_challenge_profiles_and_both_protocols(self):
        info = SimpleNamespace(st_mode=stat.S_IFREG | 0o700, st_uid=0)

        def run(command, **_kwargs):
            return runner_report(command, ok=True)

        with mock.patch.object(dns_runtime.os, "stat", return_value=info), \
                mock.patch.object(dns_runtime.os, "access", return_value=True), \
                mock.patch.object(dns_runtime, "_runner_digest", return_value="a" * 64), \
                mock.patch.object(dns_runtime, "wireguard_scope_identity", return_value="route-v1"), \
                mock.patch.object(dns_runtime, "_firewall_attached_strict",
                                  return_value=True), \
                mock.patch.object(dns_runtime, "_redirect_counters", side_effect=[
                    {"udp": 4, "tcp": 2}, {"udp": 5, "tcp": 3}]), \
                mock.patch.object(dns_runtime.subprocess, "run", side_effect=run):
            self.assertTrue(dns_runtime.client_roundtrip_proven(
                self.cfg, "all", ("wg-ip", "external-ip"), 5))

    def test_external_runner_rejects_unmatched_challenge_or_partial_counter(self):
        info = SimpleNamespace(st_mode=stat.S_IFREG | 0o700, st_uid=0)
        def wrong_report(command, **_kwargs):
            return runner_report(command, ok=True, challenge_override="wrong")
        with mock.patch.object(dns_runtime.os, "stat", return_value=info), \
                mock.patch.object(dns_runtime.os, "access", return_value=True), \
                mock.patch.object(dns_runtime, "_runner_digest", return_value="a" * 64), \
                mock.patch.object(dns_runtime, "wireguard_scope_identity", return_value="route-v1"), \
                mock.patch.object(dns_runtime, "_firewall_attached_strict",
                                  return_value=True), \
                mock.patch.object(dns_runtime, "_redirect_counters",
                                  return_value={"udp": 1, "tcp": 1}), \
                mock.patch.object(dns_runtime.subprocess, "run", side_effect=wrong_report):
            self.assertFalse(dns_runtime.client_roundtrip_proven(
                self.cfg, "all", ("wg-ip",), 5))

    def test_external_runner_rejects_wrong_owned_answer(self):
        info = SimpleNamespace(st_mode=stat.S_IFREG | 0o700, st_uid=0)

        def wrong_answer(command, **_kwargs):
            report = runner_report(command, ok=True)
            payload = json.loads(report.stdout)
            payload["profiles"]["wg-ip"]["dns"]["tcp"]["answer_ipv4"] = "192.0.2.99"
            return SimpleNamespace(returncode=0, stdout=json.dumps(payload))

        with mock.patch.object(dns_runtime.os, "stat", return_value=info), \
                mock.patch.object(dns_runtime.os, "access", return_value=True), \
                mock.patch.object(dns_runtime, "_runner_digest", return_value="a" * 64), \
                mock.patch.object(dns_runtime, "wireguard_scope_identity",
                                  return_value="route-v1"), \
                mock.patch.object(dns_runtime, "_firewall_attached_strict",
                                  return_value=True), \
                mock.patch.object(dns_runtime, "_redirect_counters",
                                  return_value={"udp": 1, "tcp": 1}), \
                mock.patch.object(dns_runtime.subprocess, "run",
                                  side_effect=wrong_answer):
            self.assertFalse(dns_runtime.client_roundtrip_proven(
                self.cfg, "all", ("wg-ip",), 5))

    def test_runner_outcomes_keep_transport_failures_separate(self):
        command = [
            dns_runtime.CANARY_RUNNER, "--challenge", "a" * 32,
            "--route-generation", "route-v1",
            "--qname", ("a" * 32) + ".canary.redut.example",
            "--expected-ipv4", "192.0.2.53", "--profiles", "wg-ip"]
        report = runner_report(command, ok=True)
        payload = json.loads(report.stdout)
        payload["profiles"]["wg-ip"]["dns"]["tcp"]["answer_ipv4"] = "192.0.2.99"
        report.stdout = json.dumps(payload)
        outcomes = dns_runtime._runner_report_outcomes(
            report, "a" * 32, "route-v1",
            ("a" * 32) + ".canary.redut.example", "192.0.2.53",
            ("wg-ip",))
        self.assertEqual(outcomes, {
            "udp": True, "tcp": False,
            "application_dns": True, "controls": True})

    def test_external_runner_proves_primary_failure_for_every_profile_and_transport(self):
        info = SimpleNamespace(st_mode=stat.S_IFREG | 0o700, st_uid=0)

        def run(command, **_kwargs):
            self.assertIn("primary-failure", command)
            return runner_report(command, ok=False)

        with mock.patch.object(dns_runtime.os, "stat", return_value=info), \
                mock.patch.object(dns_runtime.os, "access", return_value=True), \
                mock.patch.object(dns_runtime, "_runner_digest", return_value="a" * 64), \
                mock.patch.object(dns_runtime, "wireguard_scope_identity", return_value="route-v1"), \
                mock.patch.object(dns_runtime.subprocess, "run", side_effect=run):
            self.assertTrue(dns_runtime.client_primary_failure_proven(
                self.cfg, ("wg-ip", "external-ip"), 5))

    def test_primary_failure_rejects_broken_hostname_controls(self):
        info = SimpleNamespace(st_mode=stat.S_IFREG | 0o700, st_uid=0)

        def broken_control(command, **_kwargs):
            report = runner_report(command, ok=False)
            payload = json.loads(report.stdout)
            payload["profiles"]["wg-ip"]["controls"][0]["hostname"] = False
            return SimpleNamespace(returncode=0, stdout=json.dumps(payload))

        with mock.patch.object(dns_runtime.os, "stat", return_value=info), \
                mock.patch.object(dns_runtime.os, "access", return_value=True), \
                mock.patch.object(dns_runtime, "_runner_digest", return_value="a" * 64), \
                mock.patch.object(dns_runtime, "wireguard_scope_identity",
                                  return_value="route-v1"), \
                mock.patch.object(dns_runtime.subprocess, "run",
                                  side_effect=broken_control):
            self.assertFalse(dns_runtime.client_primary_failure_proven(
                self.cfg, ("wg-ip",), 5))

    @staticmethod
    def _successful_runner(command, **_kwargs):
        return runner_report(command, ok=True)

    def test_candidate_preflight_uses_exact_peer_without_global_redirect(self):
        firewall = FakeFirewall()
        info = SimpleNamespace(st_mode=stat.S_IFREG | 0o700, st_uid=0)
        with mock.patch.object(dns_runtime.apply_mod, "run_cmd", side_effect=firewall), \
                mock.patch.object(dns_runtime.os, "stat", return_value=info), \
                mock.patch.object(dns_runtime.os, "access", return_value=True), \
                mock.patch.object(dns_runtime, "_runner_digest", return_value="a" * 64), \
                mock.patch.object(dns_runtime, "wireguard_scope_identity", return_value="route-v1"), \
                mock.patch.object(dns_runtime, "_redirect_counters", side_effect=[
                    {"udp": 2, "tcp": 1}, {"udp": 3, "tcp": 2}]), \
                mock.patch.object(dns_runtime.subprocess, "run",
                                  side_effect=self._successful_runner):
            dns_runtime.stage_listener_acl(self.cfg, "peer:10.77.0.9")
            dns_runtime.activate_firewall(self.cfg, "peer:10.77.0.9")
            self.assertTrue(dns_runtime.client_candidate_preflight_proven(
                self.cfg, "peer:10.77.0.9", ("wg-ip", "external-ip"), 5))
        self.assertNotIn(("nat", dns_runtime.GLOBAL_CHAIN), firewall.chains)
        self.assertIn(("filter", dns_runtime.SCOPED_INPUT_CHAIN), firewall.chains)

    def test_primary_recovery_bypass_is_exact_and_removed_after_proof(self):
        firewall = FakeFirewall()
        self.cfg["dns_rescue"]["canary_peer_ipv4"] = "10.77.0.9"
        info = SimpleNamespace(st_mode=stat.S_IFREG | 0o700, st_uid=0)
        with mock.patch.object(dns_runtime.apply_mod, "run_cmd", side_effect=firewall):
            dns_runtime.activate_firewall(self.cfg, "all")
        with mock.patch.object(dns_runtime.apply_mod, "run_cmd", side_effect=firewall), \
                mock.patch.object(dns_runtime.os, "stat", return_value=info), \
                mock.patch.object(dns_runtime.os, "access", return_value=True), \
                mock.patch.object(dns_runtime, "_runner_digest", return_value="a" * 64), \
                mock.patch.object(dns_runtime, "wireguard_scope_ready", return_value=True), \
                mock.patch.object(dns_runtime, "wireguard_scope_identity", return_value="route-v1"), \
                mock.patch.object(dns_runtime.subprocess, "run",
                                  side_effect=self._successful_runner):
            self.assertTrue(dns_runtime.client_primary_recovery_proven(
                self.cfg, ("wg-ip", "external-ip"), 5))
        self.assertNotIn(("nat", dns_runtime.PRIMARY_TEST_CHAIN), firewall.chains)
        self.assertFalse(any(
            dns_runtime.PRIMARY_TEST_CHAIN in rule
            for rule in firewall.chains[("nat", "PREROUTING")]))

    def test_crash_residue_primary_bypass_is_neutralized_and_removed(self):
        firewall = FakeFirewall()
        firewall.chains[("nat", dns_runtime.PRIMARY_TEST_CHAIN)] = [("-j", "RETURN")]
        firewall.chains[("nat", "PREROUTING")].append((
            "-i", "wg0", "-s", "10.77.0.9/32", "-p", "udp", "--dport", "53",
            "-j", dns_runtime.PRIMARY_TEST_CHAIN))
        with mock.patch.object(dns_runtime.apply_mod, "run_cmd", side_effect=firewall):
            self.assertTrue(dns_runtime.scrub_primary_test_bypass(self.cfg))
        self.assertNotIn(("nat", dns_runtime.PRIMARY_TEST_CHAIN), firewall.chains)
        self.assertFalse(any(
            dns_runtime.PRIMARY_TEST_CHAIN in rule
            for rule in firewall.chains[("nat", "PREROUTING")]))

    def test_runner_digest_mismatch_is_rejected(self):
        info = SimpleNamespace(st_mode=stat.S_IFREG | 0o700, st_uid=0)
        with mock.patch.object(dns_runtime.os, "stat", return_value=info), \
                mock.patch.object(dns_runtime.os, "access", return_value=True), \
                mock.patch.object(dns_runtime, "_runner_digest", return_value="b" * 64):
            self.assertFalse(dns_runtime.peer_canary_runner_ready(self.cfg))


if __name__ == "__main__":
    unittest.main(verbosity=2)
