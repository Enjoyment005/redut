# -*- coding: utf-8 -*-
"""Linux runtime boundary for the isolated DNS Rescue gateway.

The module never edits the main sing-box config.  A second process gets its own
config, state directory and systemd unit.  All kernel changes use owned chains
and are verified after mutation.
"""
import copy
import ipaddress
import json
import os
import tempfile
from urllib.parse import urlparse

import apply as apply_mod

IPTABLES = "/usr/sbin/iptables"
CHAIN = "REDUT_DNS_RESCUE"
CONFIG_PATH = "/etc/redut-dns-rescue/config.json"
UNIT = "redut-dns-rescue.service"


class DNSRuntimeError(Exception):
    pass


def wireguard_ip(cfg):
    subnet = ipaddress.ip_network(cfg.get("subnet"), strict=False)
    return str(next(subnet.hosts()))


def _safe_endpoint(value):
    parsed = urlparse(str(value or ""))
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.port:
        raise DNSRuntimeError("resolver endpoint must be HTTPS without credentials or custom port")
    try:
        ipaddress.ip_address(parsed.hostname or "")
    except ValueError as error:
        raise DNSRuntimeError("resolver endpoint must use a literal IP") from error
    if parsed.path not in ("/dns-query", "/resolve"):
        raise DNSRuntimeError("unsupported resolver path")
    return str(value)


def _proxy_outbound(main_config):
    for outbound in (main_config or {}).get("outbounds", []):
        if outbound.get("tag") == "socks-out" and outbound.get("type") in ("socks", "http"):
            out = copy.deepcopy(outbound)
            out["tag"] = "rescue-proxy"
            return out
    raise DNSRuntimeError("main proxy outbound unavailable")


def build_gateway_config(cfg, slot, main_config=None):
    dns_cfg = cfg["dns_rescue"]
    listen = dns_cfg.get("listen_ip") or wireguard_ip(cfg)
    ipaddress.ip_address(listen)
    endpoint = _safe_endpoint(slot.get("endpoint"))
    via = "rescue-direct"
    outbounds = [{"type": "direct", "tag": "rescue-direct"},
                 {"type": "dns", "tag": "rescue-dns"}]
    if slot.get("transport") == "proxy":
        proxy = _proxy_outbound(main_config or {})
        outbounds.insert(1, proxy)
        via = "rescue-proxy"
    elif slot.get("transport") != "direct":
        raise DNSRuntimeError("invalid rescue transport")
    return {
        "log": {"level": "warn", "timestamp": True},
        "dns": {"servers": [{"tag": "rescue-upstream", "address": endpoint,
                              "detour": via}],
                "final": "rescue-upstream", "strategy": "ipv4_only",
                "independent_cache": True},
        "inbounds": [{"type": "direct", "tag": "rescue-in", "listen": listen,
                      "listen_port": int(dns_cfg["listen_port"]), "sniff": True}],
        "outbounds": outbounds,
        "route": {"rules": [{"inbound": ["rescue-in"], "protocol": "dns",
                              "outbound": "rescue-dns"}], "final": via},
    }


def stage_config(cfg, slot, main_config, path=CONFIG_PATH):
    """Write/check candidate beside live config, then atomically replace it."""
    candidate = build_gateway_config(cfg, slot, main_config)
    parent = os.path.dirname(path)
    os.makedirs(parent, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".config.", suffix=".json", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(candidate, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o600)
        rc, out = apply_mod.run_cmd([cfg.get("singbox_bin") or "sing-box", "check", "-c", tmp])
        if rc != 0:
            raise DNSRuntimeError("gateway config check failed: %s" % str(out)[:300])
        os.replace(tmp, path)
        return candidate
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _scope_source(cfg, scope):
    subnet = ipaddress.ip_network(cfg["subnet"], strict=False)
    if scope == "all":
        return str(subnet)
    if not str(scope).startswith("peer:"):
        raise DNSRuntimeError("invalid rescue scope")
    address = ipaddress.ip_address(str(scope).split(":", 1)[1])
    if address.version != 4 or address not in subnet:
        raise DNSRuntimeError("peer scope is outside the WireGuard subnet")
    return str(address) + "/32"


def _rule(cfg, scope="all", chain=CHAIN):
    dns_cfg = cfg["dns_rescue"]
    return ["-s", _scope_source(cfg, scope), "-p", "udp", "--dport", "53",
            "-j", "REDIRECT", "--to-ports", str(dns_cfg["listen_port"])]


def _tcp_rule(cfg, scope="all", chain=CHAIN):
    rule = _rule(cfg, scope, chain)
    rule[rule.index("udp")] = "tcp"
    return rule


def activate_firewall(cfg, scope="all"):
    """Install a single owned PREROUTING jump and an isolated redirect chain."""
    commands = [
        [IPTABLES, "-t", "nat", "-N", CHAIN],
        [IPTABLES, "-t", "nat", "-F", CHAIN],
    ]
    for command in commands:
        rc, out = apply_mod.run_cmd(command)
        if rc != 0 and command[3] != "-N":
            raise DNSRuntimeError("firewall setup failed: %s" % str(out)[:200])
    source = _scope_source(cfg, scope)
    # Drop excess queries before redirecting.  The name is constant and local
    # to the owned chain, so another subsystem cannot collide with it.
    for protocol in ("udp", "tcp"):
        limited = ["-s", source, "-p", protocol, "--dport", "53", "-m", "hashlimit",
                   "--hashlimit-above", "%s/second" % int(cfg["dns_rescue"]["qps_per_peer"]),
                   "--hashlimit-mode", "srcip", "--hashlimit-name", "redut_dns_%s" % protocol,
                   "-j", "DROP"]
        rc, out = apply_mod.run_cmd([IPTABLES, "-t", "nat", "-A", CHAIN] + limited)
        if rc != 0:
            raise DNSRuntimeError("rate-limit rule failed: %s" % str(out)[:200])
    for rule in (_rule(cfg, scope), _tcp_rule(cfg, scope)):
        rc, out = apply_mod.run_cmd([IPTABLES, "-t", "nat", "-A", CHAIN] + rule)
        if rc != 0:
            raise DNSRuntimeError("redirect rule failed: %s" % str(out)[:200])
    jump = [IPTABLES, "-t", "nat", "-C", "PREROUTING", "-i", "wg0",
            "-p", "udp", "--dport", "53", "-j", CHAIN]
    rc, _ = apply_mod.run_cmd(jump)
    if rc != 0:
        add = jump[:3] + ["-I"] + jump[4:]
        rc, out = apply_mod.run_cmd(add)
        if rc != 0:
            raise DNSRuntimeError("PREROUTING jump failed: %s" % str(out)[:200])
    # TCP needs its own jump; rules are protocol-scoped to avoid touching other owners.
    jump_tcp = list(jump)
    jump_tcp[jump_tcp.index("udp")] = "tcp"
    rc, _ = apply_mod.run_cmd(jump_tcp)
    if rc != 0:
        add = jump_tcp[:3] + ["-I"] + jump_tcp[4:]
        rc, out = apply_mod.run_cmd(add)
        if rc != 0:
            raise DNSRuntimeError("TCP PREROUTING jump failed: %s" % str(out)[:200])
    if not firewall_effective(cfg, scope=scope):
        raise DNSRuntimeError("firewall activation not effective")


def firewall_effective(cfg, scope="all"):
    for protocol in ("udp", "tcp"):
        check = [IPTABLES, "-t", "nat", "-C", "PREROUTING", "-i", "wg0",
                 "-p", protocol, "--dport", "53", "-j", CHAIN]
        if apply_mod.run_cmd(check)[0] != 0:
            return False
        rule = _rule(cfg, scope) if protocol == "udp" else _tcp_rule(cfg, scope)
        if apply_mod.run_cmd([IPTABLES, "-t", "nat", "-C", CHAIN] + rule)[0] != 0:
            return False
    return True


def deactivate_firewall(cfg, scope="all"):
    for protocol in ("udp", "tcp"):
        delete = [IPTABLES, "-t", "nat", "-D", "PREROUTING", "-i", "wg0",
                  "-p", protocol, "--dport", "53", "-j", CHAIN]
        while apply_mod.run_cmd(delete)[0] == 0:
            pass
    apply_mod.run_cmd([IPTABLES, "-t", "nat", "-F", CHAIN])
    apply_mod.run_cmd([IPTABLES, "-t", "nat", "-X", CHAIN])
    # Exact chain checks now fail because the chain is gone; this is the desired
    # fail-open state for the rescue subsystem.
    return not firewall_effective(cfg, scope=scope)


def service_start():
    rc, out = apply_mod.run_cmd(["systemctl", "restart", UNIT])
    if rc != 0:
        raise DNSRuntimeError("gateway service failed: %s" % str(out)[:200])


def service_stop():
    apply_mod.run_cmd(["systemctl", "stop", UNIT])


def service_active():
    return apply_mod.run_cmd(["systemctl", "is-active", "--quiet", UNIT])[0] == 0
