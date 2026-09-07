# -*- coding: utf-8 -*-
"""Linux runtime boundary for the isolated DNS Rescue gateway.

The module never edits the main sing-box config.  A second process gets its own
config, state directory and systemd unit.  All kernel changes use owned chains
and are verified after mutation.
"""
import copy
import hashlib
import ipaddress
import json
import os
import re
import shlex
import socket
import stat
import subprocess
import tempfile
import time
import uuid
from urllib.parse import urlparse

import apply as apply_mod

try:
    import grp
except ImportError:  # Windows-only unit tests; runtime mutation is Linux-only
    grp = None

IPTABLES = "/usr/sbin/iptables"
IPTABLES_SAVE = "/usr/sbin/iptables-save"
IP = "/usr/sbin/ip"
WG = "/usr/bin/wg"
CONNTRACK = "/usr/sbin/conntrack"
GLOBAL_CHAIN = "REDUT_DNS_RESCUE_GLOBAL"
SCOPED_CHAIN = "REDUT_DNS_RESCUE_SCOPED"
GLOBAL_INPUT_CHAIN = "REDUT_DNS_RESCUE_GLOBAL_INPUT"
SCOPED_INPUT_CHAIN = "REDUT_DNS_RESCUE_SCOPED_INPUT"
LEGACY_CHAIN = "REDUT_DNS_RESCUE"
LEGACY_INPUT_CHAIN = "REDUT_DNS_RESCUE_INPUT"
PRIMARY_TEST_CHAIN = "REDUT_DNS_PRIMARY_TEST"
PREFLIGHT_INPUT_CHAIN = "REDUT_DNS_PREFLIGHT_INPUT"
# Compatibility aliases for callers/tests that mean node-wide rescue.
CHAIN = GLOBAL_CHAIN
INPUT_CHAIN = GLOBAL_INPUT_CHAIN
CONFIG_PATH = "/etc/redut-dns-rescue/config.json"
UNIT = "redut-dns-rescue.service"
PREFLIGHT_UNIT = "redut-dns-rescue-preflight.service"
CANARY_RUNNER = "/usr/local/libexec/redut-dns-canary"
DEFAULT_SINGBOX = "/usr/local/bin/sing-box"
PREFLIGHT_ROOT = "/run/redut-dns-rescue-controller"
PREFLIGHT_CONFIG_PATH = PREFLIGHT_ROOT + "/preflight.json"
PREFLIGHT_STATE_PATH = PREFLIGHT_ROOT + "/preflight-state"
PREFLIGHT_RUNTIME_MAX_SEC = 45
CLIENT_OPERATION_MARK = "/var/lib/vpn-panel/wg-client-operation.json"
_PROTOCOLS = ("udp", "tcp")
_MAX_DUPLICATE_RULES = 32


def _owned_pairs():
    # Legacy pair is cleanup-only so an upgrade from 1.13.0 cannot stop the
    # listener while an old redirect is still attached.
    return ((GLOBAL_CHAIN, GLOBAL_INPUT_CHAIN),
            (SCOPED_CHAIN, SCOPED_INPUT_CHAIN),
            (LEGACY_CHAIN, LEGACY_INPUT_CHAIN))


class DNSRuntimeError(Exception):
    pass


def _remaining_timeout(deadline_monotonic=None, cap=5.0):
    if deadline_monotonic is None:
        return float(cap)
    remaining = float(deadline_monotonic) - time.monotonic()
    if remaining <= 0:
        raise DNSRuntimeError("DNS Rescue operation deadline exceeded")
    return max(0.1, min(float(cap), remaining))


def _cmd(command, deadline_monotonic=None, cap=5.0):
    return apply_mod.run_cmd(
        command, timeout=_remaining_timeout(deadline_monotonic, cap))


def _fsync_directory(path):
    if os.name != "posix":
        return
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_fd = os.open(path, directory_flags)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _ensure_preflight_controller_paths():
    """Create/verify a root-owned parent that the network service cannot rename.

    The leaf state directory is group-writable for sing-box, but its parent is
    not. Existing paths are never chmod/chown'ed by pathname: symlinks or
    attacker-created inodes are rejected instead of followed.
    """
    if os.name != "posix":
        os.makedirs(PREFLIGHT_STATE_PATH, mode=0o770, exist_ok=True)
        return
    group_id = grp.getgrnam("redut-dns").gr_gid
    created_root = False
    try:
        os.mkdir(PREFLIGHT_ROOT, 0o750)
        created_root = True
    except FileExistsError:
        pass
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        root_fd = os.open(PREFLIGHT_ROOT, flags)
    except OSError as error:
        raise DNSRuntimeError("unsafe preflight controller root") from error
    try:
        root_info = os.fstat(root_fd)
        if created_root:
            os.fchown(root_fd, 0, group_id)
            os.fchmod(root_fd, 0o750)
            root_info = os.fstat(root_fd)
        if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != 0
                or root_info.st_gid != group_id
                or stat.S_IMODE(root_info.st_mode) != 0o750):
            raise DNSRuntimeError("unsafe preflight controller root metadata")
        state_name = os.path.basename(PREFLIGHT_STATE_PATH)
        created_state = False
        try:
            os.mkdir(state_name, 0o770, dir_fd=root_fd)
            created_state = True
        except FileExistsError:
            pass
        try:
            state_fd = os.open(state_name, flags, dir_fd=root_fd)
        except OSError as error:
            raise DNSRuntimeError("unsafe preflight state directory") from error
        try:
            state_info = os.fstat(state_fd)
            if created_state:
                os.fchown(state_fd, 0, group_id)
                os.fchmod(state_fd, 0o770)
                state_info = os.fstat(state_fd)
            if (not stat.S_ISDIR(state_info.st_mode) or state_info.st_uid != 0
                    or state_info.st_gid != group_id
                    or stat.S_IMODE(state_info.st_mode) != 0o770):
                raise DNSRuntimeError("unsafe preflight state metadata")
        finally:
            os.close(state_fd)
    finally:
        os.close(root_fd)


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
    endpoint_host = urlparse(endpoint).hostname
    if str(slot.get("sni") or "").strip() != endpoint_host:
        raise DNSRuntimeError("resolver TLS identity must equal the literal endpoint IP")
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


def stage_config(cfg, slot, main_config, path=CONFIG_PATH, deadline_monotonic=None):
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
        rc, out = _cmd([cfg.get("singbox_bin") or DEFAULT_SINGBOX,
                        "check", "-c", tmp],
                       deadline_monotonic)
        if rc != 0:
            raise DNSRuntimeError("gateway config check failed: %s" % str(out)[:300])
        if os.name == "posix":
            os.chown(tmp, 0, grp.getgrnam("redut-dns").gr_gid)
            os.chmod(tmp, 0o640)
        with open(tmp, "r+b") as handle:
            expected_digest = hashlib.sha256(handle.read()).hexdigest()
            # Persist the final owner/mode together with the contents before
            # publishing the inode.  A directory fsync alone does not make
            # preceding inode metadata durable across power loss.
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        # Persist the rename itself, not only the file contents. Without the
        # directory fsync a power loss may resurrect the old name or lose it.
        _fsync_directory(parent)
        info = os.stat(path)
        with open(path, "rb") as handle:
            actual_digest = hashlib.sha256(handle.read()).hexdigest()
        if not stat.S_ISREG(info.st_mode) or actual_digest != expected_digest:
            raise DNSRuntimeError("gateway config activation is not durable")
        if os.name == "posix":
            expected_gid = grp.getgrnam("redut-dns").gr_gid
            if (info.st_uid != 0 or info.st_gid != expected_gid
                    or stat.S_IMODE(info.st_mode) != 0o640):
                raise DNSRuntimeError("gateway config ownership/mode is unsafe")
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


def _chains(scope):
    if scope == "all":
        return GLOBAL_CHAIN, GLOBAL_INPUT_CHAIN
    if str(scope).startswith("peer:"):
        return SCOPED_CHAIN, SCOPED_INPUT_CHAIN
    raise DNSRuntimeError("invalid rescue scope")


def _rule(cfg, scope="all", chain=CHAIN):
    dns_cfg = cfg["dns_rescue"]
    return ["-s", _scope_source(cfg, scope), "-p", "udp", "--dport", "53",
            "-j", "REDIRECT", "--to-ports", str(dns_cfg["listen_port"])]


def _tcp_rule(cfg, scope="all", chain=CHAIN):
    rule = _rule(cfg, scope, chain)
    rule[rule.index("udp")] = "tcp"
    return rule


def _input_jump(cfg, protocol, target=INPUT_CHAIN):
    dns_cfg = cfg["dns_rescue"]
    listen = dns_cfg.get("listen_ip") or wireguard_ip(cfg)
    return ["-d", listen, "-p", protocol, "--dport", str(dns_cfg["listen_port"]),
            "-j", target]


def _input_allow(cfg, scope, protocol):
    return ["-i", "wg0", "-s", _scope_source(cfg, scope), "-p", protocol,
            "--dport", str(cfg["dns_rescue"]["listen_port"]), "-j", "ACCEPT"]


def _loopback_allow(cfg, protocol):
    return ["-i", "lo", "-p", protocol, "--dport",
            str(cfg["dns_rescue"]["listen_port"]), "-j", "ACCEPT"]


def _tcp_connection_limit(cfg, scope):
    return ["-i", "wg0", "-s", _scope_source(cfg, scope), "-p", "tcp", "--syn",
            "--dport", str(cfg["dns_rescue"]["listen_port"]),
            "-m", "connlimit", "--connlimit-above",
            str(cfg["dns_rescue"]["tcp_connections_per_peer"]),
            "--connlimit-mask", "32", "-j", "DROP"]


def _listener_udp_rate_limit(cfg, scope):
    return ["-i", "wg0", "-s", _scope_source(cfg, scope), "-p", "udp",
            "--dport", str(cfg["dns_rescue"]["listen_port"]),
            "-m", "hashlimit", "--hashlimit-above",
            "%s/second" % int(cfg["dns_rescue"]["qps_per_peer"]),
            "--hashlimit-burst", str(cfg["dns_rescue"]["qps_burst_per_peer"]),
            "--hashlimit-mode", "srcip", "--hashlimit-name",
            "rd_l_%s" % ("g" if scope == "all" else "s"),
            "-j", "DROP"]


def _listener_tcp_packet_rate_limit(cfg, scope):
    """Bound persistent TCP pipelines after conntrack's first packet.

    NAT PREROUTING sees only the first packet of an established redirected
    flow, so the query hashlimit there cannot constrain pipelined DNS/TCP.
    INPUT sees every client packet. A small protocol-overhead multiplier keeps
    normal ACK/query traffic usable while retaining a hard per-source bound.
    """
    rate = max(1, int(cfg["dns_rescue"]["qps_per_peer"])) * 4
    burst = max(1, int(cfg["dns_rescue"]["qps_burst_per_peer"])) * 4
    return ["-i", "wg0", "-s", _scope_source(cfg, scope), "-p", "tcp",
            "--dport", str(cfg["dns_rescue"]["listen_port"]),
            "-m", "hashlimit", "--hashlimit-above", "%s/second" % rate,
            "--hashlimit-burst", str(burst), "--hashlimit-mode", "srcip",
            "--hashlimit-name", "rd_l_%s_t" % (
                "g" if scope == "all" else "s"), "-j", "DROP"]


def _query_rate_limit(cfg, scope, protocol):
    return ["-s", _scope_source(cfg, scope), "-p", protocol, "--dport", "53",
            "-m", "hashlimit", "--hashlimit-above",
            "%s/second" % int(cfg["dns_rescue"]["qps_per_peer"]),
            "--hashlimit-burst", str(cfg["dns_rescue"]["qps_burst_per_peer"]),
            "--hashlimit-mode", "srcip", "--hashlimit-name",
            "rd_n_%s_%s" % ("g" if scope == "all" else "s", protocol[0]),
            "-j", "DROP"]


def _jump(table, parent, protocol, target, cfg):
    if parent == "PREROUTING":
        return ["-i", "wg0", "-p", protocol, "--dport", "53", "-j", target]
    return _input_jump(cfg, protocol, target)


def _listener_staging_drop(cfg, protocol):
    """Temporary fail-closed guard used while a referenced ACL is rebuilt."""
    block = cfg["dns_rescue"]
    listen = block.get("listen_ip") or wireguard_ip(cfg)
    return ["-d", listen, "-p", protocol, "--dport",
            str(block["listen_port"]), "-j", "DROP"]


def _listener_staging_guard_present(cfg, deadline_monotonic=None):
    return any(_rule_present_strict(
        "filter", "INPUT", _listener_staging_drop(cfg, protocol),
        deadline_monotonic) for protocol in _PROTOCOLS)


def _rule_present_strict(table, chain, rule, deadline_monotonic=None):
    rc, out = _cmd([IPTABLES, "-t", table, "-C", chain] + list(rule),
                   deadline_monotonic)
    if rc == 0:
        return True
    if rc == 1:
        return False
    raise DNSRuntimeError("cannot inspect %s/%s rule: %s" % (table, chain, str(out)[:200]))


def _chain_present_strict(table, chain, deadline_monotonic=None):
    rc, out = _cmd([IPTABLES, "-t", table, "-S", chain], deadline_monotonic)
    if rc == 0:
        return True
    if rc == 1:
        return False
    raise DNSRuntimeError("cannot inspect %s/%s chain: %s" % (table, chain, str(out)[:200]))


def _create_and_flush_chain(table, chain, deadline_monotonic=None):
    if not _chain_present_strict(table, chain, deadline_monotonic):
        rc, out = _cmd([IPTABLES, "-t", table, "-N", chain], deadline_monotonic)
        if rc != 0:
            raise DNSRuntimeError("cannot create %s/%s chain: %s"
                                  % (table, chain, str(out)[:200]))
    rc, out = _cmd([IPTABLES, "-t", table, "-F", chain], deadline_monotonic)
    if rc != 0:
        raise DNSRuntimeError("cannot flush %s/%s chain: %s"
                              % (table, chain, str(out)[:200]))


def _append_rule(table, chain, rule, label, deadline_monotonic=None):
    rc, out = _cmd([IPTABLES, "-t", table, "-A", chain] + list(rule),
                   deadline_monotonic)
    if rc != 0:
        raise DNSRuntimeError("%s failed: %s" % (label, str(out)[:200]))


def _ensure_jump(table, parent, rule, label, deadline_monotonic=None):
    if _rule_present_strict(table, parent, rule, deadline_monotonic):
        return
    rc, out = _cmd([IPTABLES, "-t", table, "-I", parent] + list(rule),
                   deadline_monotonic)
    if rc != 0:
        raise DNSRuntimeError("%s failed: %s" % (label, str(out)[:200]))


def _drain_dns_conntrack(cfg, scope, deadline_monotonic=None):
    """Delete only pre-cutover IPv4 DNS flows for the declared WG source."""
    source = _scope_source(cfg, scope)
    for protocol in _PROTOCOLS:
        rc, out = _cmd([CONNTRACK, "-D", "-f", "ipv4", "-p", protocol,
                        "-s", source, "--dport", "53"], deadline_monotonic)
        # conntrack exits 1 when no matching entry existed; that is drained.
        if rc not in (0, 1):
            raise DNSRuntimeError("cannot drain %s DNS conntrack: %s"
                                  % (protocol, str(out)[:200]))


def _listener_acl_effective(cfg, scope, deadline_monotonic=None,
                            allow_staging_guard=False):
    _chain, input_chain = _chains(scope)
    if (not allow_staging_guard
            and _listener_staging_guard_present(cfg, deadline_monotonic)):
        return False
    if (_chain_present_strict("filter", PREFLIGHT_INPUT_CHAIN,
                              deadline_monotonic)
            or _references_to_chain("filter", "INPUT", PREFLIGHT_INPUT_CHAIN,
                                    deadline_monotonic)):
        return False
    # A valid narrow chain is not a valid guard if a stale global/legacy INPUT
    # pair exists beside it.  Service restart is authorized only by one
    # exclusive owned ACL scope.
    for _other_chain, other_input_chain in _owned_pairs():
        if other_input_chain == input_chain:
            continue
        if (_chain_present_strict("filter", other_input_chain,
                                  deadline_monotonic)
                or _references_to_chain("filter", "INPUT", other_input_chain,
                                        deadline_monotonic)):
            return False
    if not _chain_present_strict("filter", input_chain, deadline_monotonic):
        return False
    for protocol in _PROTOCOLS:
        if not _rule_present_strict(
                "filter", "INPUT",
                _jump("filter", "INPUT", protocol, input_chain, cfg),
                deadline_monotonic):
            return False
        if not _rule_present_strict("filter", input_chain,
                                    _loopback_allow(cfg, protocol),
                                    deadline_monotonic):
            return False
        if not _rule_present_strict("filter", input_chain,
                                    _input_allow(cfg, scope, protocol),
                                    deadline_monotonic):
            return False
    if not _rule_present_strict("filter", input_chain,
                                _listener_udp_rate_limit(cfg, scope),
                                deadline_monotonic):
        return False
    if not _rule_present_strict("filter", input_chain,
                                _listener_tcp_packet_rate_limit(cfg, scope),
                                deadline_monotonic):
        return False
    if not _rule_present_strict("filter", input_chain,
                                _tcp_connection_limit(cfg, scope),
                                deadline_monotonic):
        return False
    return _rule_present_strict("filter", input_chain, ["-j", "DROP"],
                                deadline_monotonic)


def stage_listener_acl(cfg, scope="all", deadline_monotonic=None):
    """Install the high-port deny/allow guard before the listener can start."""
    _chain, input_chain = _chains(scope)
    try:
        # A chain can already be referenced after a crash/reconcile.  Protect
        # the listener port in the parent chain before flushing it so a live
        # jump never exposes an empty or half-built allowlist.
        for protocol in _PROTOCOLS:
            _ensure_jump("filter", "INPUT", _listener_staging_drop(cfg, protocol),
                         "%s listener staging guard" % protocol.upper(),
                         deadline_monotonic)
        _create_and_flush_chain("filter", input_chain, deadline_monotonic)
        for protocol in _PROTOCOLS:
            _append_rule("filter", input_chain, _loopback_allow(cfg, protocol),
                         "loopback listener ACL", deadline_monotonic)
        _append_rule("filter", input_chain, _listener_udp_rate_limit(cfg, scope),
                     "UDP listener rate limit", deadline_monotonic)
        _append_rule("filter", input_chain,
                     _listener_tcp_packet_rate_limit(cfg, scope),
                     "TCP listener packet rate limit", deadline_monotonic)
        _append_rule("filter", input_chain, _tcp_connection_limit(cfg, scope),
                     "TCP connection limit", deadline_monotonic)
        for protocol in _PROTOCOLS:
            _append_rule("filter", input_chain, _input_allow(cfg, scope, protocol),
                         "WireGuard listener ACL", deadline_monotonic)
        _append_rule("filter", input_chain, ["-j", "DROP"],
                     "listener deny rule", deadline_monotonic)
        for protocol in _PROTOCOLS:
            _ensure_jump("filter", "INPUT",
                         _jump("filter", "INPUT", protocol, input_chain, cfg),
                         "%s INPUT jump" % protocol.upper(), deadline_monotonic)
        if not _listener_acl_effective(
                cfg, scope, deadline_monotonic, allow_staging_guard=True):
            raise DNSRuntimeError("listener ACL is not effective")
        for protocol in _PROTOCOLS:
            _delete_rule_all("filter", "INPUT",
                             _listener_staging_drop(cfg, protocol),
                             deadline_monotonic)
        if not _listener_acl_effective(cfg, scope, deadline_monotonic):
            raise DNSRuntimeError("listener ACL staging guard removal is not proven")
        return True
    except Exception:
        # Do not remove INPUT guards here: this helper cannot prove that the
        # main listener is inactive.  Fail open for client DNS by detaching NAT,
        # but leave the parent DROP/ACL residue for coordinator reconciliation.
        try:
            deactivate_redirect(cfg, scope=scope,
                                deadline_monotonic=time.monotonic() + 10.0)
        except Exception:
            pass
        raise


def _preflight_jump(cfg, protocol):
    block = cfg["dns_rescue"]
    listen = block.get("listen_ip") or wireguard_ip(cfg)
    return ["-d", listen, "-p", protocol, "--dport",
            str(block["preflight_port"]), "-j", PREFLIGHT_INPUT_CHAIN]


def _preflight_allow(cfg, scope, protocol):
    return ["-i", "wg0", "-s", _scope_source(cfg, scope), "-p", protocol,
            "--dport", str(cfg["dns_rescue"]["preflight_port"]), "-j", "ACCEPT"]


def _preflight_loopback(cfg, protocol):
    return ["-i", "lo", "-p", protocol, "--dport",
            str(cfg["dns_rescue"]["preflight_port"]), "-j", "ACCEPT"]


def _preflight_udp_limit(cfg, scope):
    return ["-i", "wg0", "-s", _scope_source(cfg, scope), "-p", "udp",
            "--dport", str(cfg["dns_rescue"]["preflight_port"]),
            "-m", "hashlimit", "--hashlimit-above",
            "%s/second" % int(cfg["dns_rescue"]["qps_per_peer"]),
            "--hashlimit-burst", str(cfg["dns_rescue"]["qps_burst_per_peer"]),
            "--hashlimit-mode", "srcip", "--hashlimit-name", "rd_p_u",
            "-j", "DROP"]


def _preflight_tcp_limit(cfg, scope):
    return ["-i", "wg0", "-s", _scope_source(cfg, scope), "-p", "tcp", "--syn",
            "--dport", str(cfg["dns_rescue"]["preflight_port"]),
            "-m", "connlimit", "--connlimit-above",
            str(cfg["dns_rescue"]["tcp_connections_per_peer"]),
            "--connlimit-mask", "32", "-j", "DROP"]


def _preflight_acl_effective(cfg, scope, deadline_monotonic=None):
    if not _chain_present_strict("filter", PREFLIGHT_INPUT_CHAIN,
                                 deadline_monotonic):
        return False
    for protocol in _PROTOCOLS:
        if (not _rule_present_strict(
                "filter", "INPUT", _preflight_jump(cfg, protocol),
                deadline_monotonic)
                or not _rule_present_strict(
                    "filter", PREFLIGHT_INPUT_CHAIN,
                    _preflight_loopback(cfg, protocol), deadline_monotonic)
                or not _rule_present_strict(
                    "filter", PREFLIGHT_INPUT_CHAIN,
                    _preflight_allow(cfg, scope, protocol), deadline_monotonic)):
            return False
    return (_rule_present_strict(
                "filter", PREFLIGHT_INPUT_CHAIN,
                _preflight_udp_limit(cfg, scope), deadline_monotonic)
            and _rule_present_strict(
                "filter", PREFLIGHT_INPUT_CHAIN,
                _preflight_tcp_limit(cfg, scope), deadline_monotonic)
            and _rule_present_strict(
                "filter", PREFLIGHT_INPUT_CHAIN, ["-j", "DROP"],
                deadline_monotonic))


def _stage_preflight_acl(cfg, scope, deadline_monotonic=None):
    if not str(scope).startswith("peer:"):
        raise DNSRuntimeError("candidate preflight requires one exact peer")
    _create_and_flush_chain("filter", PREFLIGHT_INPUT_CHAIN, deadline_monotonic)
    for protocol in _PROTOCOLS:
        _append_rule("filter", PREFLIGHT_INPUT_CHAIN,
                     _preflight_loopback(cfg, protocol),
                     "preflight loopback ACL", deadline_monotonic)
    _append_rule("filter", PREFLIGHT_INPUT_CHAIN,
                 _preflight_udp_limit(cfg, scope),
                 "preflight UDP rate limit", deadline_monotonic)
    _append_rule("filter", PREFLIGHT_INPUT_CHAIN,
                 _preflight_tcp_limit(cfg, scope),
                 "preflight TCP connection limit", deadline_monotonic)
    for protocol in _PROTOCOLS:
        _append_rule("filter", PREFLIGHT_INPUT_CHAIN,
                     _preflight_allow(cfg, scope, protocol),
                     "preflight peer ACL", deadline_monotonic)
    _append_rule("filter", PREFLIGHT_INPUT_CHAIN, ["-j", "DROP"],
                 "preflight deny rule", deadline_monotonic)
    for protocol in _PROTOCOLS:
        _ensure_jump("filter", "INPUT", _preflight_jump(cfg, protocol),
                     "%s preflight INPUT jump" % protocol.upper(),
                     deadline_monotonic)
    if not _preflight_acl_effective(cfg, scope, deadline_monotonic):
        raise DNSRuntimeError("candidate preflight ACL is not effective")


def _scrub_preflight_acl(cfg, deadline_monotonic=None):
    errors = []
    try:
        _delete_owned_references(
            "filter", "INPUT", PREFLIGHT_INPUT_CHAIN, deadline_monotonic)
    except DNSRuntimeError as error:
        errors.append(str(error))
    try:
        _remove_chain("filter", PREFLIGHT_INPUT_CHAIN, deadline_monotonic)
    except DNSRuntimeError as error:
        errors.append(str(error))
    if (_chain_present_strict("filter", PREFLIGHT_INPUT_CHAIN,
                              deadline_monotonic)
            or _references_to_chain(
                "filter", "INPUT", PREFLIGHT_INPUT_CHAIN,
                deadline_monotonic)):
        raise DNSRuntimeError("candidate preflight ACL cleanup is not proven: "
                              + "; ".join(errors)[:300])


def _delete_rule_all(table, chain, rule, deadline_monotonic=None):
    command = [IPTABLES, "-t", table, "-D", chain] + list(rule)
    for _unused in range(_MAX_DUPLICATE_RULES):
        rc, out = _cmd(command, deadline_monotonic)
        if rc == 0:
            continue
        if rc == 1:
            return
        raise DNSRuntimeError("cannot delete %s/%s rule: %s"
                              % (table, chain, str(out)[:200]))
    raise DNSRuntimeError("too many duplicate rules in %s/%s" % (table, chain))


def _references_to_chain(table, parent, target, deadline_monotonic=None):
    rc, output = _cmd([IPTABLES, "-t", table, "-S", parent], deadline_monotonic)
    if rc != 0:
        raise DNSRuntimeError("cannot inspect %s/%s references" % (table, parent))
    found = []
    for line in str(output or "").splitlines():
        try:
            tokens = shlex.split(line)
        except ValueError:
            continue
        if (len(tokens) >= 4 and tokens[0] == "-A" and tokens[1] == parent
                and "-j" in tokens):
            try:
                matches = tokens[tokens.index("-j") + 1] == target
            except IndexError:
                matches = False
            if matches:
                found.append(tokens[2:])
    return found


def _delete_owned_references(table, parent, target, deadline_monotonic=None):
    """Delete every jump to an exact Redut-owned chain, despite config drift."""
    for rule in _references_to_chain(
            table, parent, target, deadline_monotonic):
        _delete_rule_all(table, parent, rule, deadline_monotonic)
    if _references_to_chain(table, parent, target, deadline_monotonic):
        raise DNSRuntimeError("references to owned %s/%s chain remain"
                              % (table, target))


def _scrub_primary_test_bypass(cfg, deadline_monotonic=None):
    """Neutralize and remove every crash residue of the temporary bypass."""
    errors = []
    try:
        if _chain_present_strict("nat", PRIMARY_TEST_CHAIN, deadline_monotonic):
            # First make any unknown stale reference harmless.
            rc, out = _cmd([IPTABLES, "-t", "nat", "-F", PRIMARY_TEST_CHAIN],
                           deadline_monotonic)
            if rc != 0:
                raise DNSRuntimeError("cannot neutralize primary test chain: %s"
                                      % str(out)[:200])
    except DNSRuntimeError as error:
        errors.append(str(error))
    try:
        for rule in _references_to_chain(
                "nat", "PREROUTING", PRIMARY_TEST_CHAIN, deadline_monotonic):
            _delete_rule_all("nat", "PREROUTING", rule, deadline_monotonic)
    except DNSRuntimeError as error:
        errors.append(str(error))
    try:
        _remove_chain("nat", PRIMARY_TEST_CHAIN, deadline_monotonic)
    except DNSRuntimeError as error:
        errors.append(str(error))
    try:
        remains = (_chain_present_strict(
            "nat", PRIMARY_TEST_CHAIN, deadline_monotonic)
            or bool(_references_to_chain(
                "nat", "PREROUTING", PRIMARY_TEST_CHAIN, deadline_monotonic)))
    except DNSRuntimeError as error:
        errors.append(str(error))
        remains = True
    if remains or errors:
        raise DNSRuntimeError("primary recovery bypass cleanup not proven: "
                              + "; ".join(errors)[:500])
    return True


def scrub_primary_test_bypass(cfg, deadline_monotonic=None):
    deadline = (deadline_monotonic if deadline_monotonic is not None
                else time.monotonic() + 10.0)
    return _scrub_primary_test_bypass(cfg, deadline)


def _remove_chain(table, chain, deadline_monotonic=None):
    if not _chain_present_strict(table, chain, deadline_monotonic):
        return
    rc, out = _cmd([IPTABLES, "-t", table, "-F", chain], deadline_monotonic)
    if rc != 0:
        raise DNSRuntimeError("cannot clear %s/%s chain: %s"
                              % (table, chain, str(out)[:200]))
    rc, out = _cmd([IPTABLES, "-t", table, "-X", chain], deadline_monotonic)
    if rc != 0:
        raise DNSRuntimeError("cannot remove %s/%s chain: %s"
                              % (table, chain, str(out)[:200]))


def activate_firewall(cfg, scope="all", deadline_monotonic=None):
    """Attach exact owned DNS rules; never flush a built-in chain.

    INPUT ACLs are attached before PREROUTING, so a partial activation cannot
    expose the high listener port. A failed activation removes only NAT here;
    the coordinator stops the listener before it removes the protective ACL.
    """
    source = _scope_source(cfg, scope)
    chain, input_chain = _chains(scope)
    try:
        # A scoped canary and a node-wide rescue have distinct owned chains.
        # The coordinator permits only one active session, while distinct names
        # make stale artifacts attributable and safe to reconcile.
        _create_and_flush_chain("nat", chain, deadline_monotonic)
        if not _listener_acl_effective(cfg, scope, deadline_monotonic):
            stage_listener_acl(cfg, scope, deadline_monotonic)
        for protocol in _PROTOCOLS:
            limited = _query_rate_limit(cfg, scope, protocol)
            _append_rule("nat", chain, limited, "rate-limit rule", deadline_monotonic)
        _append_rule("nat", chain, _rule(cfg, scope, chain), "UDP redirect rule",
                     deadline_monotonic)
        _append_rule("nat", chain, _tcp_rule(cfg, scope, chain), "TCP redirect rule",
                     deadline_monotonic)

        for protocol in _PROTOCOLS:
            _ensure_jump("nat", "PREROUTING",
                         _jump("nat", "PREROUTING", protocol, chain, cfg),
                         "%s PREROUTING jump" % protocol.upper(), deadline_monotonic)
        _drain_dns_conntrack(cfg, scope, deadline_monotonic)
        if not _firewall_attached_strict(cfg, scope, deadline_monotonic):
            raise DNSRuntimeError("firewall activation not effective")
        return True
    except Exception as error:
        try:
            cleanup_deadline = time.monotonic() + 10.0
            deactivate_redirect(cfg, scope=scope,
                                deadline_monotonic=cleanup_deadline)
        except Exception as cleanup_error:
            raise DNSRuntimeError("firewall activation failed (%s); cleanup failed (%s)"
                                  % (type(error).__name__, type(cleanup_error).__name__)) from error
        if isinstance(error, DNSRuntimeError):
            raise
        raise DNSRuntimeError("firewall activation failed: %s" % type(error).__name__) from error


def _firewall_attached_strict(cfg, scope="all", deadline_monotonic=None):
    if _listener_staging_guard_present(cfg, deadline_monotonic):
        return False
    if (_chain_present_strict("nat", PRIMARY_TEST_CHAIN, deadline_monotonic)
            or _references_to_chain(
                "nat", "PREROUTING", PRIMARY_TEST_CHAIN, deadline_monotonic)):
        return False
    chain, input_chain = _chains(scope)
    if (_chain_present_strict("filter", PREFLIGHT_INPUT_CHAIN, deadline_monotonic)
            or _references_to_chain(
                "filter", "INPUT", PREFLIGHT_INPUT_CHAIN, deadline_monotonic)):
        return False
    # Exactly one owned scope may exist. A valid declared pair does not make a
    # stale/global/legacy pair harmless: another jump can silently broaden the
    # intercepted clients beyond durable state.
    for other_chain, other_input_chain in _owned_pairs():
        if (other_chain, other_input_chain) == (chain, input_chain):
            continue
        if (_chain_present_strict("nat", other_chain, deadline_monotonic)
                or _chain_present_strict("filter", other_input_chain,
                                         deadline_monotonic)
                or _references_to_chain("nat", "PREROUTING", other_chain,
                                        deadline_monotonic)
                or _references_to_chain("filter", "INPUT", other_input_chain,
                                        deadline_monotonic)):
            return False
    if not _chain_present_strict("nat", chain, deadline_monotonic):
        return False
    if not _chain_present_strict("filter", input_chain, deadline_monotonic):
        return False
    for protocol in _PROTOCOLS:
        if not _rule_present_strict(
                "nat", "PREROUTING",
                _jump("nat", "PREROUTING", protocol, chain, cfg), deadline_monotonic):
            return False
        redirect = (_rule(cfg, scope, chain) if protocol == "udp"
                    else _tcp_rule(cfg, scope, chain))
        if not _rule_present_strict(
                "nat", chain, _query_rate_limit(cfg, scope, protocol),
                deadline_monotonic):
            return False
        if not _rule_present_strict("nat", chain, redirect, deadline_monotonic):
            return False
        if not _rule_present_strict(
                "filter", "INPUT",
                _jump("filter", "INPUT", protocol, input_chain, cfg), deadline_monotonic):
            return False
        if not _rule_present_strict("filter", input_chain,
                                    _loopback_allow(cfg, protocol), deadline_monotonic):
            return False
        if not _rule_present_strict("filter", input_chain,
                                    _input_allow(cfg, scope, protocol), deadline_monotonic):
            return False
    if not _rule_present_strict("filter", input_chain,
                                _listener_udp_rate_limit(cfg, scope),
                                deadline_monotonic):
        return False
    if not _rule_present_strict("filter", input_chain,
                                _listener_tcp_packet_rate_limit(cfg, scope),
                                deadline_monotonic):
        return False
    if not _rule_present_strict("filter", input_chain,
                                _tcp_connection_limit(cfg, scope),
                                deadline_monotonic):
        return False
    return _rule_present_strict("filter", input_chain, ["-j", "DROP"],
                                deadline_monotonic)


def firewall_attached(cfg, deadline_monotonic=None):
    """Return whether any owned firewall artifact is still attached/present.

    This intentionally differs from ``firewall_effective``: a partial jump or
    orphan chain is drift that reconciliation must see, not an idle state.
    """
    deadline_monotonic = (deadline_monotonic if deadline_monotonic is not None
                          else time.monotonic() + 10.0)
    try:
        if _listener_staging_guard_present(cfg, deadline_monotonic):
            return True
        if (_chain_present_strict("nat", PRIMARY_TEST_CHAIN, deadline_monotonic)
                or _references_to_chain(
                    "nat", "PREROUTING", PRIMARY_TEST_CHAIN,
                    deadline_monotonic)):
            return True
        if (_chain_present_strict("filter", PREFLIGHT_INPUT_CHAIN,
                                  deadline_monotonic)
                or _references_to_chain(
                    "filter", "INPUT", PREFLIGHT_INPUT_CHAIN,
                    deadline_monotonic)):
            return True
        for chain, input_chain in _owned_pairs():
            if _chain_present_strict("nat", chain, deadline_monotonic):
                return True
            if _chain_present_strict("filter", input_chain, deadline_monotonic):
                return True
            for protocol in _PROTOCOLS:
                if _rule_present_strict(
                        "nat", "PREROUTING",
                        _jump("nat", "PREROUTING", protocol, chain, cfg),
                        deadline_monotonic):
                    return True
                if _rule_present_strict(
                        "filter", "INPUT",
                        _jump("filter", "INPUT", protocol, input_chain, cfg),
                        deadline_monotonic):
                    return True
        return False
    except (DNSRuntimeError, KeyError, TypeError, ValueError):
        # Unknown is treated as attached by mutation callers.  This prevents a
        # failed inspection from authorizing service_stop while a redirect may
        # still exist.
        return True


def firewall_effective(cfg, scope="all", deadline_monotonic=None):
    """Compatibility wrapper used by the coordinator for a declared scope."""
    deadline_monotonic = (deadline_monotonic if deadline_monotonic is not None
                          else time.monotonic() + 10.0)
    try:
        return _firewall_attached_strict(cfg, scope=scope,
                                         deadline_monotonic=deadline_monotonic)
    except (DNSRuntimeError, KeyError, TypeError, ValueError):
        return False


def _redirect_detached_strict(cfg, deadline_monotonic=None):
    if (_chain_present_strict("nat", PRIMARY_TEST_CHAIN, deadline_monotonic)
            or _references_to_chain(
                "nat", "PREROUTING", PRIMARY_TEST_CHAIN, deadline_monotonic)):
        return False
    for chain, _input_chain in _owned_pairs():
        for protocol in _PROTOCOLS:
            if _rule_present_strict(
                    "nat", "PREROUTING",
                    _jump("nat", "PREROUTING", protocol, chain, cfg),
                    deadline_monotonic):
                return False
        if _chain_present_strict("nat", chain, deadline_monotonic):
            return False
    return True


def redirect_detached(cfg, deadline_monotonic=None):
    try:
        deadline = (deadline_monotonic if deadline_monotonic is not None
                    else time.monotonic() + 10.0)
        return _redirect_detached_strict(cfg, deadline)
    except (DNSRuntimeError, KeyError, TypeError, ValueError):
        return False


def listener_guard_effective(cfg, scope="all", deadline_monotonic=None):
    try:
        deadline = (deadline_monotonic if deadline_monotonic is not None
                    else time.monotonic() + 10.0)
        return _listener_acl_effective(cfg, scope, deadline)
    except (DNSRuntimeError, KeyError, TypeError, ValueError):
        return False


def deactivate_redirect(cfg, scope="all", deadline_monotonic=None):
    """Neutralize NAT and drain old mappings while the listener stays guarded.

    Removing a REDIRECT rule does not invalidate conntrack's translation for an
    already established DNS flow.  The targeted drain must therefore happen
    after detachment is proven, but before the coordinator stops the listener.
    """
    errors = []
    try:
        _scrub_primary_test_bypass(cfg, deadline_monotonic)
    except DNSRuntimeError as error:
        errors.append(str(error))
    for chain, _input_chain in _owned_pairs():
        for protocol in _PROTOCOLS:
            try:
                _delete_rule_all(
                    "nat", "PREROUTING",
                    _jump("nat", "PREROUTING", protocol, chain, cfg),
                    deadline_monotonic)
            except DNSRuntimeError as error:
                errors.append(str(error))
        try:
            _delete_owned_references(
                "nat", "PREROUTING", chain, deadline_monotonic)
        except DNSRuntimeError as error:
            errors.append(str(error))
        try:
            _remove_chain("nat", chain, deadline_monotonic)
        except DNSRuntimeError as error:
            errors.append(str(error))
    if not _redirect_detached_strict(cfg, deadline_monotonic):
        raise DNSRuntimeError("DNS redirect detachment not proven: "
                              + ("; ".join(errors)[:500] or "NAT artifacts remain"))
    # Cleanup removes every owned NAT generation, including stale broader
    # chains. Drain the full WG subnet so no pre-existing translation can keep
    # sending a different peer to the listener after it is stopped.
    _drain_dns_conntrack(cfg, "all", deadline_monotonic)
    return True


def remove_listener_acl(cfg, scope="all", deadline_monotonic=None):
    """Remove high-port guards only after the listener is proven inactive."""
    try:
        inactive = not _service_active_strict(deadline_monotonic)
    except DNSRuntimeError:
        inactive = False
    if not inactive:
        raise DNSRuntimeError("listener ACL removal requires proven inactive service")
    errors = []
    for protocol in _PROTOCOLS:
        try:
            _delete_rule_all("filter", "INPUT",
                             _listener_staging_drop(cfg, protocol),
                             deadline_monotonic)
        except DNSRuntimeError as error:
            errors.append(str(error))
    try:
        scrub_candidate_sidecar(cfg, deadline_monotonic)
    except DNSRuntimeError as error:
        errors.append(str(error))
    for _chain, input_chain in _owned_pairs():
        for protocol in _PROTOCOLS:
            try:
                _delete_rule_all(
                    "filter", "INPUT",
                    _jump("filter", "INPUT", protocol, input_chain, cfg),
                    deadline_monotonic)
            except DNSRuntimeError as error:
                errors.append(str(error))
        try:
            _delete_owned_references(
                "filter", "INPUT", input_chain, deadline_monotonic)
        except DNSRuntimeError as error:
            errors.append(str(error))
        try:
            _remove_chain("filter", input_chain, deadline_monotonic)
        except DNSRuntimeError as error:
            errors.append(str(error))
    if errors:
        raise DNSRuntimeError("listener ACL cleanup not proven: "
                              + "; ".join(errors)[:500])
    return True


def _firewall_detached_strict(cfg, deadline_monotonic=None):
    if _listener_staging_guard_present(cfg, deadline_monotonic):
        return False
    if (_chain_present_strict("nat", PRIMARY_TEST_CHAIN, deadline_monotonic)
            or _references_to_chain(
                "nat", "PREROUTING", PRIMARY_TEST_CHAIN, deadline_monotonic)):
        return False
    if (_chain_present_strict("filter", PREFLIGHT_INPUT_CHAIN,
                              deadline_monotonic)
            or _references_to_chain(
                "filter", "INPUT", PREFLIGHT_INPUT_CHAIN,
                deadline_monotonic)):
        return False
    for chain, input_chain in _owned_pairs():
        for protocol in _PROTOCOLS:
            if _rule_present_strict(
                    "nat", "PREROUTING",
                    _jump("nat", "PREROUTING", protocol, chain, cfg),
                    deadline_monotonic):
                return False
            if _rule_present_strict(
                    "filter", "INPUT",
                    _jump("filter", "INPUT", protocol, input_chain, cfg),
                    deadline_monotonic):
                return False
        if (_chain_present_strict("nat", chain, deadline_monotonic)
                or _chain_present_strict("filter", input_chain, deadline_monotonic)):
            return False
    return True


def firewall_detached(cfg, deadline_monotonic=None):
    """Return True only after proving both owned chains and all jumps absent."""
    try:
        deadline = (deadline_monotonic if deadline_monotonic is not None
                    else time.monotonic() + 10.0)
        return _firewall_detached_strict(cfg, deadline)
    except (DNSRuntimeError, KeyError, TypeError, ValueError):
        return False


def deactivate_firewall(cfg, scope="all", deadline_monotonic=None):
    """Remove only exact owned jumps/chains and prove complete detachment.

    Cleanup continues after individual failures.  In particular, the NAT chain
    is flushed even when a jump cannot be deleted, which makes that residual
    jump return to PREROUTING instead of redirecting port 53 to a dead listener.
    The function still raises until every owned artifact is proven absent.
    """
    errors = []
    try:
        scrub_candidate_sidecar(cfg, deadline_monotonic)
    except DNSRuntimeError as error:
        errors.append(str(error))
    try:
        _scrub_primary_test_bypass(cfg, deadline_monotonic)
    except DNSRuntimeError as error:
        errors.append(str(error))
    pairs = _owned_pairs()
    for chain, input_chain in pairs:
        for protocol in _PROTOCOLS:
            for table, parent, target in (("nat", "PREROUTING", chain),
                                          ("filter", "INPUT", input_chain)):
                try:
                    _delete_rule_all(table, parent,
                                     _jump(table, parent, protocol, target, cfg),
                                     deadline_monotonic)
                except DNSRuntimeError as error:
                    errors.append(str(error))
        for table, parent, target in (("nat", "PREROUTING", chain),
                                      ("filter", "INPUT", input_chain)):
            try:
                _delete_owned_references(
                    table, parent, target, deadline_monotonic)
            except DNSRuntimeError as error:
                errors.append(str(error))

    # Always neutralize the redirect chain.  If a non-exact reference remains,
    # -X will fail and the final proof below will correctly reject cleanup.
    for chain, input_chain in pairs:
        for table, owned_chain in (("nat", chain), ("filter", input_chain)):
            try:
                _remove_chain(table, owned_chain, deadline_monotonic)
            except DNSRuntimeError as error:
                errors.append(str(error))

    # Keep the parent DROP until every owned INPUT jump/chain has been removed.
    # If a live ACL rebuild failed halfway, removing this guard earlier would
    # briefly expose the listener through that partial chain.
    for protocol in _PROTOCOLS:
        try:
            _delete_rule_all("filter", "INPUT",
                             _listener_staging_drop(cfg, protocol),
                             deadline_monotonic)
        except DNSRuntimeError as error:
            errors.append(str(error))

    try:
        detached = _firewall_detached_strict(cfg, deadline_monotonic)
    except DNSRuntimeError as error:
        errors.append(str(error))
        detached = False
    if not detached:
        detail = "; ".join(errors)[:500] or "owned firewall artifacts remain"
        raise DNSRuntimeError("DNS Rescue firewall detachment not proven: " + detail)
    return True


def _link_is_up(output):
    match = re.search(r"<([^>]*)>", str(output or ""))
    return bool(match and "UP" in {item.strip() for item in match.group(1).split(",")})


def wireguard_scope_ready(cfg, scope, deadline_monotonic=None):
    """Validate an up wg0 and exact, unique IPv4 /32 peer ownership."""
    if os.path.lexists(CLIENT_OPERATION_MARK):
        return False
    try:
        source = _scope_source(cfg, scope)
        subnet = ipaddress.ip_network(cfg["subnet"], strict=False)
    except (DNSRuntimeError, KeyError, TypeError, ValueError):
        return False
    rc, link = _cmd([IP, "-o", "link", "show", "dev", "wg0"], deadline_monotonic)
    if rc != 0 or not _link_is_up(link):
        return False
    rc, output = _cmd([WG, "show", "wg0", "allowed-ips"], deadline_monotonic)
    if rc != 0:
        return False
    networks = []
    try:
        for line in str(output or "").splitlines():
            parts = line.split(None, 1)
            if len(parts) != 2 or parts[1].strip() in ("", "(none)"):
                continue
            for raw in parts[1].split(","):
                network = ipaddress.ip_network(raw.strip(), strict=False)
                if network.version != 4 or network.prefixlen != 32 or not network.subnet_of(subnet):
                    return False
                if str(network.network_address) == wireguard_ip(cfg):
                    return False
                networks.append(network)
    except ValueError:
        return False
    if not networks:
        return False
    for index, network in enumerate(networks):
        if any(network.overlaps(other) for other in networks[index + 1:]):
            return False
    if scope == "all":
        return True
    expected = ipaddress.ip_network(source, strict=False)
    return sum(1 for network in networks if network == expected) == 1


def wireguard_scope_identity_state(cfg, scope, deadline_monotonic=None):
    """Tri-state identity proof: valid, invalid, or inspection-unknown."""
    if os.path.lexists(CLIENT_OPERATION_MARK):
        return {"status": "unknown", "identity": None}
    try:
        source = ipaddress.ip_network(_scope_source(cfg, scope), strict=False)
        subnet = ipaddress.ip_network(cfg["subnet"], strict=False)
    except (DNSRuntimeError, KeyError, TypeError, ValueError):
        return {"status": "invalid", "identity": None}
    try:
        rc, link = _cmd([IP, "-o", "link", "show", "dev", "wg0"],
                        deadline_monotonic)
        if rc != 0:
            message = str(link or "").lower()
            status = ("invalid" if any(marker in message for marker in (
                "does not exist", "cannot find device", "no such device")) else
                      "unknown")
            return {"status": status, "identity": None}
        if not _link_is_up(link):
            return {"status": "invalid", "identity": None}
        rc, output = _cmd([WG, "show", "wg0", "allowed-ips"], deadline_monotonic)
        if rc != 0:
            message = str(output or "").lower()
            status = ("invalid" if any(marker in message for marker in (
                "does not exist", "cannot find device", "no such device")) else
                      "unknown")
            return {"status": status, "identity": None}
        identities = []
        networks = []
        for line in str(output or "").splitlines():
            parts = line.split(None, 1)
            if len(parts) != 2 or parts[1].strip() in ("", "(none)"):
                continue
            public_key = parts[0].strip()
            for raw in parts[1].split(","):
                network = ipaddress.ip_network(raw.strip(), strict=False)
                if (network.version != 4 or network.prefixlen != 32
                        or not network.subnet_of(subnet)
                        or str(network.network_address) == wireguard_ip(cfg)):
                    return {"status": "invalid", "identity": None}
                networks.append(network)
                if scope == "all" or network == source:
                    identities.append("%s %s" % (public_key, network))
        if not identities or (scope != "all" and len(identities) != 1):
            return {"status": "invalid", "identity": None}
        for index, network in enumerate(networks):
            if any(network.overlaps(other) for other in networks[index + 1:]):
                return {"status": "invalid", "identity": None}
        payload = "%s\n%s" % (subnet, "\n".join(sorted(identities)))
        return {"status": "valid",
                "identity": hashlib.sha256(payload.encode("ascii")).hexdigest()}
    except DNSRuntimeError:
        return {"status": "unknown", "identity": None}
    except (KeyError, TypeError, ValueError):
        return {"status": "invalid", "identity": None}


def wireguard_scope_identity(cfg, scope, deadline_monotonic=None):
    """Return a privacy-safe digest only for a conclusive valid inventory."""
    result = wireguard_scope_identity_state(cfg, scope, deadline_monotonic)
    return result.get("identity") if result.get("status") == "valid" else None


def emergency_route_state(cfg, deadline_monotonic=None):
    """Tri-state proof for the exact direct middleman default route."""
    wan = str(cfg.get("wan") or "").strip()
    gateway = str(cfg.get("gw") or "").strip() or None
    if not wan:
        return "mismatch"
    if gateway:
        try:
            if ipaddress.ip_address(gateway).version != 4:
                return "mismatch"
        except ValueError:
            return "mismatch"
    try:
        rc, output = _cmd(
            [IP, "-4", "route", "show", "table", "middleman", "default"],
            deadline_monotonic)
    except DNSRuntimeError:
        return "unknown"
    if rc != 0:
        return "unknown"
    defaults = [line.split() for line in str(output or "").splitlines()
                if line.split() and line.split()[0] == "default"]
    if len(defaults) != 1:
        return "mismatch"
    tokens = defaults[0]
    if "nexthop" in tokens or tokens.count("dev") != 1 or tokens.count("via") > 1:
        return "mismatch"
    try:
        actual_wan = tokens[tokens.index("dev") + 1]
    except (ValueError, IndexError):
        return "mismatch"
    try:
        actual_gateway = tokens[tokens.index("via") + 1]
    except (ValueError, IndexError):
        actual_gateway = None
    return ("ready" if actual_wan == wan and actual_gateway == gateway
            else "mismatch")


def emergency_route_ready(cfg, deadline_monotonic=None):
    """Compatibility bool: only a conclusive exact direct route is ready."""
    return emergency_route_state(cfg, deadline_monotonic) == "ready"


def _redirect_counters(cfg, scope, deadline_monotonic=None):
    rc, output = _cmd([IPTABLES_SAVE, "-c", "-t", "nat"], deadline_monotonic)
    if rc != 0:
        raise DNSRuntimeError("cannot read DNS redirect counters: %s" % str(output)[:200])
    source = _scope_source(cfg, scope)
    chain, _input_chain = _chains(scope)
    port = str(cfg["dns_rescue"]["listen_port"])
    counters = {protocol: None for protocol in _PROTOCOLS}
    for line in str(output or "").splitlines():
        if not line.startswith("[") or " -A %s " % chain not in (" " + line + " "):
            continue
        try:
            tokens = shlex.split(line)
            packet_count = int(tokens[0][1:].split(":", 1)[0])
            protocol = tokens[tokens.index("-p") + 1]
            rule_source = tokens[tokens.index("-s") + 1]
            dport = tokens[tokens.index("--dport") + 1]
            target = tokens[tokens.index("-j") + 1]
            to_port = tokens[tokens.index("--to-ports") + 1]
        except (ValueError, IndexError):
            continue
        if (protocol in counters and rule_source == source and dport == "53"
                and target == "REDIRECT" and to_port == port):
            counters[protocol] = packet_count
    if any(value is None for value in counters.values()):
        raise DNSRuntimeError("DNS redirect counters are incomplete")
    return counters


def client_path_observed(cfg, scope, timeout, deadline_monotonic=None):
    """Wait boundedly for a new real packet to hit the scoped REDIRECT rule.

    This is observational evidence only.  It deliberately does not treat a
    direct query to the high listener port as proof of the WireGuard path.
    """
    try:
        duration = max(0.0, min(30.0, float(timeout)))
        if not _firewall_attached_strict(cfg, scope=scope,
                                         deadline_monotonic=deadline_monotonic):
            return False
        baseline = _redirect_counters(cfg, scope, deadline_monotonic)
        deadline = min(time.monotonic() + duration,
                       deadline_monotonic if deadline_monotonic is not None else float("inf"))
        while True:
            current = _redirect_counters(cfg, scope, deadline_monotonic)
            if any(current[item] > baseline[item] for item in _PROTOCOLS):
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(0.2, remaining))
    except (DNSRuntimeError, KeyError, TypeError, ValueError):
        return False


def _runner_digest():
    digest = hashlib.sha256()
    with open(CANARY_RUNNER, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def peer_canary_runner_ready(cfg):
    """Trust only a fixed root-owned, non-writable external client runner."""
    try:
        info = os.stat(CANARY_RUNNER)
        expected = str((cfg.get("dns_rescue") or {}).get("canary_runner_sha256") or "")
        return (len(expected) == 64 and stat.S_ISREG(info.st_mode) and info.st_uid == 0
                and not (info.st_mode & (stat.S_IWGRP | stat.S_IWOTH))
                and os.access(CANARY_RUNNER, os.X_OK)
                and _runner_digest() == expected)
    except OSError:
        return False


def _runner_command(cfg, mode, profiles, challenge, scope="all",
                    deadline_monotonic=None):
    """Build the fixed runner command and bind evidence to the WG inventory."""
    generation = wireguard_scope_identity(cfg, scope, deadline_monotonic)
    if not generation:
        raise DNSRuntimeError("WireGuard route generation is unavailable")
    block = cfg.get("dns_rescue") or {}
    suffix = str(block.get("canary_qname_suffix") or "").strip().lower().rstrip(".")
    expected_ipv4 = str(block.get("canary_expected_ipv4") or "").strip()
    try:
        ipaddress.IPv4Address(expected_ipv4)
    except ipaddress.AddressValueError as error:
        raise DNSRuntimeError("owned DNS canary IPv4 is unavailable") from error
    qname = "%s.%s" % (challenge, suffix)
    if (not suffix or len(qname) > 253
            or not re.fullmatch(r"[0-9a-f]{32}\.(?:[a-z0-9-]+\.)+[a-z0-9-]+", qname)):
        raise DNSRuntimeError("owned DNS canary suffix is unavailable")
    command = [CANARY_RUNNER, "--mode", mode, "--scope", scope,
               "--route-generation", generation, "--challenge", challenge,
               "--qname", qname, "--expected-ipv4", expected_ipv4,
               "--profiles", ",".join(profiles), "--transports", "udp,tcp"]
    return command, generation, qname, expected_ipv4


def _runner_dns_proven(item, expected_ok, qname, expected_ipv4):
    if (not isinstance(item, dict)
            or set(item) != {"ok", "qname", "answer_ipv4", "ttl"}
            or item.get("ok") is not expected_ok
            or item.get("qname") != qname):
        return False
    if expected_ok:
        ttl = item.get("ttl")
        return (item.get("answer_ipv4") == expected_ipv4
                and isinstance(ttl, int) and not isinstance(ttl, bool)
                and 0 <= ttl <= 300)
    return item.get("answer_ipv4") is None and item.get("ttl") is None


def _runner_profile_proven(item, dns_value, application_value, qname,
                           expected_ipv4):
    """Require DNS/application evidence plus two independent IP/TLS controls."""
    if not isinstance(item, dict):
        return False
    if set(item) != {"dns", "application_dns", "controls"}:
        return False
    dns = item.get("dns")
    if (not isinstance(dns, dict)
            or not _runner_dns_proven(dns.get("udp"), dns_value,
                                      qname, expected_ipv4)
            or not _runner_dns_proven(dns.get("tcp"), dns_value,
                                      qname, expected_ipv4)
            or not _runner_dns_proven(item.get("application_dns"),
                                      application_value, qname, expected_ipv4)):
        return False
    return _runner_controls_proven(item)


def _runner_controls_proven(item):
    if not isinstance(item, dict):
        return False
    controls = item.get("controls")
    if not isinstance(controls, list) or len(controls) < 2:
        return False
    identifiers = set()
    for control in controls:
        if not isinstance(control, dict) or set(control) != {
                "id", "ip_tls", "hostname"}:
            return False
        identifier = str(control.get("id") or "").strip()
        if (not identifier or identifier in identifiers
                or control.get("ip_tls") is not True
                or control.get("hostname") is not True):
            return False
        identifiers.add(identifier)
    return True


def _runner_report_evidence(proc, challenge, generation, qname, expected_ipv4,
                            profiles):
    raw = proc.stdout or ""
    if proc.returncode != 0 or len(raw.encode("utf-8", "replace")) > 4096:
        return None
    report = json.loads(raw)
    query = report.get("query") if isinstance(report, dict) else None
    if (not isinstance(report, dict)
            or set(report) != {"version", "challenge", "route_generation",
                               "query", "profiles"}
            or report.get("version") != 3
            or report.get("challenge") != challenge
            or report.get("route_generation") != generation
            or not isinstance(query, dict)
            or query != {"qname": qname, "type": "A",
                         "expected_ipv4": expected_ipv4}):
        return None
    evidence = report.get("profiles")
    if not isinstance(evidence, dict) or set(evidence) != set(profiles):
        return None
    return evidence


def _parse_runner_report(proc, challenge, generation, qname, expected_ipv4,
                         profiles, dns_value, application_value):
    evidence = _runner_report_evidence(
        proc, challenge, generation, qname, expected_ipv4, profiles)
    return (evidence is not None
            and all(_runner_profile_proven(
                evidence.get(profile), dns_value, application_value,
                qname, expected_ipv4)
                    for profile in profiles))


def _runner_report_outcomes(proc, challenge, generation, qname,
                            expected_ipv4, profiles):
    """Return only challenge-bound booleans safe for observe/UI output."""
    evidence = _runner_report_evidence(
        proc, challenge, generation, qname, expected_ipv4, profiles)
    outcomes = {"udp": False, "tcp": False,
                "application_dns": False, "controls": False}
    if evidence is None:
        return outcomes
    for transport in _PROTOCOLS:
        outcomes[transport] = all(
            isinstance(evidence.get(profile), dict)
            and isinstance(evidence[profile].get("dns"), dict)
            and _runner_dns_proven(
                evidence[profile]["dns"].get(transport), True,
                qname, expected_ipv4)
            for profile in profiles)
    outcomes["application_dns"] = all(
        isinstance(evidence.get(profile), dict)
        and _runner_dns_proven(
            evidence[profile].get("application_dns"), True,
            qname, expected_ipv4)
        for profile in profiles)
    outcomes["controls"] = all(
        _runner_controls_proven(evidence.get(profile)) for profile in profiles)
    return outcomes


def _preflight_service_active_strict(deadline_monotonic=None):
    rc, out = _cmd(["systemctl", "is-active", PREFLIGHT_UNIT],
                   deadline_monotonic)
    state = str(out or "").strip().splitlines()
    state = state[0].strip().lower() if state else ""
    if rc == 0 and state == "active":
        return True
    if rc in (3, 4) and state in ("inactive", "failed", "unknown", ""):
        return False
    raise DNSRuntimeError("cannot prove candidate sidecar state: rc=%s state=%s"
                          % (rc, state or "unknown"))


def _preflight_service_start(cfg, deadline_monotonic=None):
    if _preflight_service_active_strict(deadline_monotonic):
        raise DNSRuntimeError("candidate sidecar is already active")
    command = [
        "systemd-run", "--quiet", "--collect", "--unit=" + PREFLIGHT_UNIT,
        "--service-type=simple", "--uid=redut-dns", "--gid=redut-dns",
        "--property=NoNewPrivileges=yes", "--property=PrivateTmp=yes",
        "--property=PrivateDevices=yes", "--property=ProtectHome=yes",
        "--property=ProtectSystem=strict", "--property=MemoryMax=64M",
        "--property=TasksMax=32", "--property=LimitNOFILE=1024",
        "--property=RuntimeMaxSec=%ss" % PREFLIGHT_RUNTIME_MAX_SEC,
        "--property=RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK",
        cfg.get("singbox_bin") or DEFAULT_SINGBOX, "run", "-c",
        PREFLIGHT_CONFIG_PATH, "-D", PREFLIGHT_STATE_PATH,
    ]
    rc, out = _cmd(command, deadline_monotonic, cap=10.0)
    if rc != 0 or not _preflight_service_active_strict(deadline_monotonic):
        raise DNSRuntimeError("candidate sidecar start failed: %s" % str(out)[:200])


def _preflight_service_stop(deadline_monotonic=None):
    if _preflight_service_active_strict(deadline_monotonic):
        rc, out = _cmd(["systemctl", "stop", PREFLIGHT_UNIT],
                       deadline_monotonic, cap=10.0)
        if rc != 0:
            raise DNSRuntimeError("candidate sidecar stop failed: %s" % str(out)[:200])
    if _preflight_service_active_strict(deadline_monotonic):
        raise DNSRuntimeError("candidate sidecar remains active after stop")


def scrub_candidate_sidecar(cfg, deadline_monotonic=None):
    """Prove the transient process dead before removing its guard/config."""
    _preflight_service_stop(deadline_monotonic)
    _scrub_preflight_acl(cfg, deadline_monotonic)
    if os.path.exists(PREFLIGHT_CONFIG_PATH):
        os.unlink(PREFLIGHT_CONFIG_PATH)
        _fsync_directory(os.path.dirname(PREFLIGHT_CONFIG_PATH))
    return True


def candidate_sidecar_preflight_proven(cfg, slot, main_config, scope, profiles,
                                       timeout, deadline_monotonic=None,
                                       evidence_out=None):
    """Prove a successor on a separate guarded port before touching live DNS.

    The sidecar never receives port-53 traffic.  One exact WireGuard peer calls
    the alternate high port and returns challenge-bound UDP/TCP/application
    evidence.  Every process/config/firewall artifact is removed before the
    result can authorize a live service restart.
    """
    required = tuple(sorted(set(profiles or ())))
    if (os.name != "posix" or not required or not str(scope).startswith("peer:")
            or not peer_canary_runner_ready(cfg)):
        return False
    proven = False
    outcomes = {"udp": False, "tcp": False,
                "application_dns": False, "controls": False}
    try:
        duration = max(1.0, min(30.0, float(timeout)))
        duration = min(duration, _remaining_timeout(deadline_monotonic, duration))
        block = cfg.get("dns_rescue") or {}
        port = int(block.get("preflight_port"))
        if port == int(block.get("listen_port")):
            raise DNSRuntimeError("candidate preflight port overlaps live listener")
        sidecar_cfg = copy.deepcopy(cfg)
        sidecar_cfg["dns_rescue"] = copy.deepcopy(block)
        sidecar_cfg["dns_rescue"]["listen_port"] = port
        _ensure_preflight_controller_paths()
        stage_config(sidecar_cfg, slot, main_config, path=PREFLIGHT_CONFIG_PATH,
                     deadline_monotonic=deadline_monotonic)
        _stage_preflight_acl(cfg, scope, deadline_monotonic)
        # A fixed transient systemd unit survives coordinator death and gives
        # the next reconcile an unambiguous control-group kill target.
        _preflight_service_start(cfg, deadline_monotonic)
        listen = block.get("listen_ip") or wireguard_ip(cfg)
        ready_deadline = min(time.monotonic() + min(2.0, duration),
                             deadline_monotonic if deadline_monotonic is not None
                             else float("inf"))
        while True:
            if not _preflight_service_active_strict(deadline_monotonic):
                raise DNSRuntimeError("candidate sidecar exited before proof")
            try:
                with socket.create_connection((listen, port), timeout=0.1):
                    break
            except OSError:
                if time.monotonic() >= ready_deadline:
                    raise DNSRuntimeError("candidate sidecar did not start listening")
                time.sleep(0.05)
        challenge = uuid.uuid4().hex
        command, generation, qname, expected_ipv4 = _runner_command(
            cfg, "candidate-preflight", required, challenge, scope,
            deadline_monotonic)
        command.extend(["--listen", listen, "--port", str(port)])
        proc = subprocess.run(
            command, capture_output=True, text=True,
            timeout=min(duration, _remaining_timeout(deadline_monotonic, duration)),
            env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                 "LANG": "C", "LC_ALL": "C"})
        outcomes = _runner_report_outcomes(
            proc, challenge, generation, qname, expected_ipv4, required)
        proven = all(outcomes.values())
    except (DNSRuntimeError, KeyError, TypeError, ValueError, OSError,
            subprocess.SubprocessError):
        proven = False
    finally:
        # Never remove the ACL/config unless systemd proved the whole transient
        # control group inactive.  Failure is surfaced to reconciliation.
        scrub_candidate_sidecar(cfg, time.monotonic() + 10.0)
    if isinstance(evidence_out, dict):
        evidence_out.update(outcomes)
    return proven


def client_candidate_preflight_proven(cfg, scope, profiles, timeout,
                                      deadline_monotonic=None):
    """Test a staged candidate through one exact WG peer before global NAT."""
    required = tuple(sorted(set(profiles or ())))
    if (not required or not str(scope).startswith("peer:")
            or not peer_canary_runner_ready(cfg)):
        return False
    try:
        duration = max(1.0, min(30.0, float(timeout)))
        duration = min(duration, _remaining_timeout(deadline_monotonic, duration))
        if not _firewall_attached_strict(cfg, scope, deadline_monotonic):
            return False
        baseline = _redirect_counters(cfg, scope, deadline_monotonic)
        challenge = uuid.uuid4().hex
        listen = (cfg.get("dns_rescue") or {}).get("listen_ip") or wireguard_ip(cfg)
        port = int((cfg.get("dns_rescue") or {}).get("listen_port"))
        command, generation, qname, expected_ipv4 = _runner_command(
            cfg, "candidate-preflight", required, challenge, scope,
            deadline_monotonic)
        command.extend(["--listen", listen, "--port", str(port)])
        proc = subprocess.run(
            command, capture_output=True, text=True, timeout=duration,
            env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                 "LANG": "C", "LC_ALL": "C"})
        if not _parse_runner_report(
                proc, challenge, generation, qname, expected_ipv4,
                required, True, True):
            return False
        current = _redirect_counters(cfg, scope, deadline_monotonic)
        return all(current[transport] > baseline[transport]
                   for transport in _PROTOCOLS)
    except (DNSRuntimeError, KeyError, TypeError, ValueError, OSError,
            subprocess.SubprocessError):
        return False


def client_roundtrip_proven(cfg, scope, profiles, timeout, deadline_monotonic=None):
    """Correlate real test-peer UDP/TCP replies with both REDIRECT counters.

    The fixed external runner performs the client-side requests, validates the
    replies and returns one bounded JSON document tied to our one-shot
    challenge. Redut accepts no client address or query payload from it.
    """
    required = tuple(sorted(set(profiles or ())))
    if not required or not peer_canary_runner_ready(cfg):
        return False
    try:
        duration = max(1.0, min(30.0, float(timeout)))
        duration = min(duration, _remaining_timeout(deadline_monotonic, duration))
        if not _firewall_attached_strict(cfg, scope=scope,
                                         deadline_monotonic=deadline_monotonic):
            return False
        baseline = _redirect_counters(cfg, scope, deadline_monotonic)
        challenge = uuid.uuid4().hex
        listen = (cfg.get("dns_rescue") or {}).get("listen_ip") or wireguard_ip(cfg)
        port = int((cfg.get("dns_rescue") or {}).get("listen_port"))
        command, generation, qname, expected_ipv4 = _runner_command(
            cfg, "rescue-roundtrip", required, challenge, scope,
            deadline_monotonic)
        command.extend(["--listen", listen, "--port", str(port)])
        proc = subprocess.run(
            command, capture_output=True, text=True, timeout=duration,
            env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                 "LANG": "C", "LC_ALL": "C"})
        if not _parse_runner_report(
                proc, challenge, generation, qname, expected_ipv4,
                required, True, True):
            return False
        current = _redirect_counters(cfg, scope, deadline_monotonic)
        return all(current[transport] > baseline[transport]
                   for transport in _PROTOCOLS)
    except (DNSRuntimeError, KeyError, TypeError, ValueError, OSError,
            subprocess.SubprocessError):
        return False


def client_primary_failure_proven(cfg, profiles, timeout, deadline_monotonic=None):
    """Prove DNS-specific failure while independent IP/TLS controls still work."""
    required = tuple(sorted(set(profiles or ())))
    if not required or not peer_canary_runner_ready(cfg):
        return False
    try:
        duration = max(1.0, min(30.0, float(timeout)))
        duration = min(duration, _remaining_timeout(deadline_monotonic, duration))
        target = str(cfg.get("dns") or "1.1.1.1")
        ipaddress.ip_address(target)
        challenge = uuid.uuid4().hex
        command, generation, qname, expected_ipv4 = _runner_command(
            cfg, "primary-failure", required, challenge, "all",
            deadline_monotonic)
        command.extend(["--dns", target, "--port", "53"])
        proc = subprocess.run(
            command, capture_output=True, text=True, timeout=duration,
            env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                 "LANG": "C", "LC_ALL": "C"})
        return _parse_runner_report(
            proc, challenge, generation, qname, expected_ipv4,
            required, False, False)
    except (DNSRuntimeError, TypeError, ValueError, OSError,
            subprocess.SubprocessError):
        return False


def client_primary_recovery_proven(cfg, profiles, timeout,
                                   deadline_monotonic=None):
    """Prove the original path through an exact temporary bypass.

    A plain query while the global REDIRECT is active would only prove rescue
    again.  This function inserts two exact source/protocol RETURN rules for the
    configured synthetic peer, drains that peer's DNS conntrack mappings, runs
    the external application proof, then removes and re-drains the bypass.
    """
    required = tuple(sorted(set(profiles or ())))
    if not required or not peer_canary_runner_ready(cfg):
        return False
    cleanup_ok = True
    scope = ""
    try:
        duration = max(1.0, min(30.0, float(timeout)))
        duration = min(duration, _remaining_timeout(deadline_monotonic, duration))
        target = str(cfg.get("dns") or "1.1.1.1")
        ipaddress.ip_address(target)
        canary_ip = str((cfg.get("dns_rescue") or {}).get("canary_peer_ipv4") or "")
        scope = "peer:" + canary_ip
        if (not canary_ip or not wireguard_scope_ready(
                cfg, scope, deadline_monotonic)):
            return False
        source = _scope_source(cfg, scope)
        _scrub_primary_test_bypass(cfg, deadline_monotonic)
        if not _firewall_attached_strict(
                cfg, scope="all", deadline_monotonic=deadline_monotonic):
            return False
        _create_and_flush_chain("nat", PRIMARY_TEST_CHAIN, deadline_monotonic)
        _append_rule("nat", PRIMARY_TEST_CHAIN, ["-j", "RETURN"],
                     "primary recovery RETURN", deadline_monotonic)
        for protocol in _PROTOCOLS:
            rule = ["-i", "wg0", "-s", source, "-p", protocol,
                    "--dport", "53", "-j", PRIMARY_TEST_CHAIN]
            _ensure_jump("nat", "PREROUTING", rule,
                         "%s primary recovery bypass" % protocol.upper(),
                         deadline_monotonic)
            if not _rule_present_strict(
                    "nat", "PREROUTING", rule, deadline_monotonic):
                raise DNSRuntimeError("primary recovery bypass is not effective")
        _drain_dns_conntrack(cfg, scope, deadline_monotonic)
        challenge = uuid.uuid4().hex
        command, generation, qname, expected_ipv4 = _runner_command(
            cfg, "primary-recovery", required, challenge, scope,
            deadline_monotonic)
        command.extend(["--dns", target, "--port", "53"])
        proc = subprocess.run(
            command, capture_output=True, text=True, timeout=duration,
            env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                 "LANG": "C", "LC_ALL": "C"})
        proven = _parse_runner_report(
            proc, challenge, generation, qname, expected_ipv4,
            required, True, True)
    except (DNSRuntimeError, TypeError, ValueError, OSError,
            subprocess.SubprocessError):
        proven = False
    finally:
        cleanup_deadline = time.monotonic() + 10.0
        try:
            _scrub_primary_test_bypass(cfg, cleanup_deadline)
        except DNSRuntimeError:
            cleanup_ok = False
        if scope:
            try:
                _drain_dns_conntrack(cfg, scope, cleanup_deadline)
            except DNSRuntimeError:
                cleanup_ok = False
    return bool(proven and cleanup_ok)


def service_start(deadline_monotonic=None):
    rc, out = _cmd(["systemctl", "restart", UNIT], deadline_monotonic, cap=10.0)
    if rc != 0:
        raise DNSRuntimeError("gateway service failed: %s" % str(out)[:200])
    if not _service_active_strict(deadline_monotonic):
        raise DNSRuntimeError("gateway service did not become active")
    return True


def service_stop(deadline_monotonic=None):
    rc, out = _cmd(["systemctl", "stop", UNIT], deadline_monotonic, cap=10.0)
    if rc != 0:
        raise DNSRuntimeError("gateway service stop failed: %s" % str(out)[:200])
    if _service_active_strict(deadline_monotonic):
        raise DNSRuntimeError("gateway service remains active after stop")
    return True


def _service_active_strict(deadline_monotonic=None):
    rc, out = _cmd(["systemctl", "is-active", UNIT], deadline_monotonic)
    state = str(out or "").strip().splitlines()
    state = state[0].strip().lower() if state else ""
    if rc == 0 and state == "active":
        return True
    if rc == 3 and state in ("inactive", "failed"):
        return False
    raise DNSRuntimeError("cannot prove gateway service state: rc=%s state=%s"
                          % (rc, state or "unknown"))


def service_active(deadline_monotonic=None):
    try:
        return _service_active_strict(deadline_monotonic)
    except DNSRuntimeError:
        return False


def service_state(deadline_monotonic=None):
    """Return active/inactive/unknown without collapsing inspection errors."""
    try:
        return "active" if _service_active_strict(deadline_monotonic) else "inactive"
    except DNSRuntimeError:
        return "unknown"


def service_inactive(deadline_monotonic=None):
    """Return True only when systemd positively reports the gateway stopped."""
    try:
        return not _service_active_strict(deadline_monotonic)
    except DNSRuntimeError:
        return False
