"""Per-contour client DNS. The sing-box file is the durable source of truth.

Provider mode passes names, rather than locally resolved addresses, to the
selected SOCKS/HTTP/VLESS exit. FakeIP mappings survive exit/core restarts.
Public DNS and service records always travel inside that same contour.
"""
import copy
import ipaddress
import json
import os
import socket
import shlex
import struct
import time
import uuid

import apply
import contours
import dns_probe

MODES = ("provider", "cloudflare", "provider_strict")
STRICT_PROXY_PORT = 10802
STRICT_PROXY_TAG = "redut-c2-proxy"
CLOSED_DNS = "redut-bootstrap"
REFUSED_RECORDS = {"action": "predefined", "rcode": "REFUSED"}
STRICT_DNS_ROUTE = {"port": 53, "action": "hijack-dns"}
FAKE = "redut-proxy-names"
PRIMARY_INBOUND = "redut-client-dns"
PRIMARY_SERVICE = "dnsmasq-redut-c1"
GUARD_SERVICE = "redut-dns-policy-guard"
EMPTY_RECORDS = {"query_type": ["AAAA", "HTTPS", "SVCB"],
                 "action": "predefined", "rcode": "NOERROR"}
WHITELIST = "/etc/dnsmasq.d/ru-whitelist.conf"


class DNSPolicyError(apply.ApplyError):
    pass


def managed(sb):
    return any(s.get("tag") == FAKE for s in sb.get("dns", {}).get("servers", []))


def strict(sb):
    """Durable policy marker: all A names belong to the provider, without exceptions."""
    return any(r.get("server") == FAKE and r.get("query_type") == "A"
               for r in sb.get("dns", {}).get("rules", []))


def mode(sb):
    if strict(sb):
        return "provider_strict"
    if any(r.get("server") == FAKE for r in sb.get("dns", {}).get("rules", [])):
        return "provider"
    return "cloudflare"


def _whitelist_lines():
    try:
        with open(WHITELIST, encoding="utf-8") as handle:
            return [line for line in handle if line.startswith("ipset=/")]
    except FileNotFoundError:
        return []


def _line_domains(line):
    return [d.lstrip(".").lower() for d in line.split("/")[1:-1] if d]


def exceptions(cfg):
    domains = {"ru", "su", "xn--p1ai", "localhost", "local", "lan", "home.arpa"}
    for line in _whitelist_lines():
        domains.update(_line_domains(line))
    canary = str((cfg.get("dns_rescue") or {}).get("canary_qname_suffix") or "").strip(".")
    if canary:
        domains.add(canary)
    return sorted(domains)


def whitelist_text(sb):
    """Never insert a synthetic address into the node's shared RU bypass set."""
    if strict(sb):
        return ""
    lines = _whitelist_lines()
    if mode(sb) != "provider":
        return "".join(lines)
    excluded = set()
    for rule in sb.get("dns", {}).get("rules", []):
        if rule.get("server") == FAKE:
            for condition in rule.get("rules", []):
                if condition.get("invert"):
                    excluded.update(condition.get("domain_suffix", []))
    return "".join(line for line in lines if all(
        any(d == suffix or d.endswith("." + suffix) for suffix in excluded)
        for d in _line_domains(line)))


def prepare(cfg, sb, selected):
    """Pure config transform; preserve exits, routing, and unrelated DNS rules."""
    if selected not in MODES:
        raise DNSPolicyError("Неизвестный режим DNS")
    if selected == "provider_strict" and not contours.secondary(cfg):
        raise DNSPolicyError("Строгий режим доступен только во втором контуре")
    result = copy.deepcopy(sb)
    dns = result.setdefault("dns", {})
    servers = dns.setdefault("servers", [])
    public = {"tag": "proxy-dns", "type": "https", "server": "1.1.1.1",
              "server_port": 443, "path": "/dns-query", "detour": "socks-out"}
    servers[:] = [s for s in servers if s.get("tag") not in ("proxy-dns", FAKE)]
    servers += [public, {"tag": FAKE, "type": "fakeip", "inet4_range":
                        "198.19.128.0/17" if contours.secondary(cfg) else "198.19.0.0/17"}]
    rules = [r for r in dns.get("rules", []) if r.get("server") != FAKE and r not in (EMPTY_RECORDS, REFUSED_RECORDS)]
    # An imported/custom rule can override provider DNS. Refuse to advertise a
    # mode we cannot guarantee, rather than silently deleting that rule.
    if rules:
        raise DNSPolicyError("В конфигурации есть собственные DNS-правила; требуется их согласование")
    if selected == "provider":
        rules = [copy.deepcopy(EMPTY_RECORDS),
                 {"type": "logical", "mode": "and", "rules": [
                     {"query_type": "A"}, {"domain_suffix": exceptions(cfg), "invert": True}],
                  "action": "route", "server": FAKE, "rewrite_ttl": 60}]
    dns.update({"rules": rules, "final": "proxy-dns", "strategy": "ipv4_only",
                "reverse_mapping": True})
    # Keep the mapping cache when switching back to public DNS: clients can
    # still use previously cached synthetic addresses until their TTL expires.
    cache = result.setdefault("experimental", {}).setdefault("cache_file", {})
    cache.update({"enabled": True, "store_fakeip": True,
                  "path": os.path.join(os.path.dirname(cfg["db"]), "dns-fakeip.db")})
    route = result.setdefault("route", {})
    route["default_domain_resolver"] = "proxy-dns"
    inbounds = result.setdefault("inbounds", [])
    if not contours.secondary(cfg):
        inbounds[:] = [i for i in inbounds if i.get("tag") != PRIMARY_INBOUND]
        inbounds.append({"type": "direct", "tag": PRIMARY_INBOUND, "listen": "127.0.0.1",
                         "listen_port": 5353, "override_address": "1.1.1.1", "override_port": 53})
    inbounds[:] = [i for i in inbounds if i.get("tag") != STRICT_PROXY_TAG]
    tags = {PRIMARY_INBOUND, "c2-dns"}
    route_rules = [r for r in route.setdefault("rules", []) if r.get("inbound") not in tuple(tags) and r != STRICT_DNS_ROUTE]
    route["rules"] = [{"inbound": "c2-dns" if contours.secondary(cfg) else PRIMARY_INBOUND,
                       "action": "hijack-dns"}] + route_rules
    if selected == "provider_strict":
        _prepare_strict(cfg, result)
    else:
        # An explicit return to a normal mode restores the owned bootstrap.
        # This also permits future hostname endpoints in those normal modes.
        closed = {"type": "hosts", "tag": CLOSED_DNS, "path": ["/dev/null"]}
        for index, server in enumerate(servers):
            if server == closed:
                servers[index] = {"type": "udp", "tag": CLOSED_DNS, "server": "9.9.9.9",
                                  "detour": "redut-direct"}
                if not any(o.get("tag") == "redut-direct" for o in result.get("outbounds", [])):
                    direct = {"type": "direct", "tag": "redut-direct"}
                    if cfg.get("wan"):
                        direct["bind_interface"] = cfg["wan"]
                    result.setdefault("outbounds", []).append(direct)
    return result


def _prepare_strict(cfg, result):
    """No recursive DNS fallback and no direct or alternate outbound path."""
    dns = result["dns"]
    unknown = [s for s in dns["servers"] if s.get("tag") not in
               (FAKE, CLOSED_DNS, "proxy-dns", "redut-bootstrap")]
    if unknown:
        raise DNSPolicyError("Собственные DNS-серверы несовместимы со строгим режимом")
    dns["servers"] = [s for s in dns["servers"] if s.get("tag") == FAKE]
    dns["rules"] = [copy.deepcopy(EMPTY_RECORDS),
                    {"query_type": "A", "action": "route", "server": FAKE, "rewrite_ttl": 60},
                    copy.deepcopy(REFUSED_RECORDS)]
    # sing-box requires a non-FakeIP default. An empty local hosts source
    # satisfies that constraint without providing a recursive/network fallback.
    dns["servers"].append({"type": "hosts", "tag": CLOSED_DNS, "path": ["/dev/null"]})
    dns["final"] = CLOSED_DNS
    route = result["route"]
    route.pop("default_domain_resolver", None)
    route["final"] = "socks-out"
    route["rules"].insert(0, copy.deepcopy(STRICT_DNS_ROUTE))
    # Unknown actions may resolve destinations locally, or route to another
    # exit. Refuse the configuration instead of silently reinterpreting it.
    for rule in route["rules"]:
        if (rule.get("action", "route") not in ("sniff", "hijack-dns", "reject", "route")
                or rule.get("outbound") not in (None, "socks-out", "http-tg")
                or "rules" in rule or "rule_set" in rule):
            raise DNSPolicyError("Собственное правило маршрутизации несовместимо со строгим режимом")
    exits = []
    for outbound in result["outbounds"]:
        if outbound.get("tag") == "redut-direct" and outbound.get("type") == "direct":
            continue
        if (outbound.get("tag") not in ("socks-out", "http-tg")
                or outbound.get("type") not in ("vless", "socks", "http") or outbound.get("detour")):
            raise DNSPolicyError("Строгому режиму нужен один выбранный прокси без запасного выхода")
        try:
            if ipaddress.ip_address(outbound["server"]).version != 4:
                raise ValueError()
        except (KeyError, ValueError):
            raise DNSPolicyError("Адрес сервера провайдера должен быть закреплён как IPv4") from None
        if outbound.get("domain_resolver") not in (None, CLOSED_DNS):
            raise DNSPolicyError("Неизвестный bootstrap резолвер провайдера")
        # Keep connection identity and manual pins unchanged. The existing
        # resolver tag now references the empty local hosts source, never WAN.
        exits.append(outbound)
    if not any(o.get("tag") == "socks-out" for o in exits):
        raise DNSPolicyError("Сначала выберите работающий прокси")
    result["outbounds"] = exits
    gateway = str(next(ipaddress.ip_network(cfg["subnet"]).hosts()))
    result["inbounds"].append({"type": "mixed", "tag": STRICT_PROXY_TAG,
                                "listen": gateway, "listen_port": STRICT_PROXY_PORT})


def guard_transition(cfg, target=None):
    """Close C2 before changing or recovering either side of a strict policy."""
    if not contours.secondary(cfg):
        return
    live = apply.load_json(cfg["singbox_config"])
    if strict(live) or (target is not None and strict(target)):
        contours.strict_transition_guard(cfg)


def status(cfg, pool=None):
    sb = apply.load_json(cfg["singbox_config"])
    current = mode(sb) if managed(sb) or contours.secondary(cfg) else "legacy"
    emergency = os.path.exists(cfg.get("emergency_intent") or "/nonexistent")
    return {"contour": "2" if contours.secondary(cfg) else "1", "mode": current,
            "managed": managed(sb), "emergency": emergency,
            "strict": strict(sb),
            "proxy_endpoint": ("%s:%d" % (next(ipaddress.ip_network(cfg["subnet"]).hosts()), STRICT_PROXY_PORT)
                               if strict(sb) and contours.secondary(cfg) else None),
            "service_records": "refused" if strict(sb) else "public-via-proxy",
            "available": any(o.get("tag") == "socks-out" and o.get("server")
                             and o.get("type") in ("socks", "http", "vless")
                             for o in sb.get("outbounds", [])),
            "pending": bool(pool and any(o.get("kind") == "dns-policy"
                                          for o in pool.unfinished_operations()))}


def sync_emergency(cfg, direct):
    """Called by the existing emergency transaction while holding its lock."""
    path = cfg.get("singbox_config")
    conf_path, _ = _primary_paths(cfg)
    if not path or (not os.path.isfile(path) and not os.path.exists(conf_path)):
        return
    if managed(apply.load_json(path)):
        reconcile(cfg, _locked=True, restart=True, direct=direct)


def _primary_paths(cfg):
    parent = os.path.dirname(cfg.get("_source") or "/etc/vpn-panel/config.json")
    return (os.path.join(parent, "dns-primary.conf"),
            os.path.join(cfg.get("_test_unit_dir") or "/etc/systemd/system", PRIMARY_SERVICE + ".service"))


def reconcile(cfg, _locked=False, restart=False, direct=None):
    """Derive the client gateway from the selected contour's core config.

    Primary uses its own dnsmasq listener; the server's port 53 resolver never
    receives FakeIP answers. Secondary already has an isolated DNS gateway.
    """
    with apply._maybe_lock(cfg, _locked):
        sb = apply.load_json(cfg["singbox_config"])
        if contours.secondary(cfg):
            contours.sync_dns(contours.main_config(cfg), restart=restart)
            return
        conf_path, unit_path = _primary_paths(cfg)
        enabled = managed(sb)
        unit_dir = os.path.dirname(unit_path)
        guard_path = os.path.join(unit_dir, GUARD_SERVICE + ".service")
        dropin_path = os.path.join(unit_dir, "wg-quick@wg0.service.d", "40-redut-dns.conf")
        if not enabled and not any(os.path.exists(p) for p in (conf_path, guard_path, dropin_path)):
            return
        if enabled:
            gateway = str(next(ipaddress.ip_network(cfg["subnet"]).hosts()))
            emergency = (os.path.exists(cfg.get("emergency_intent") or "/nonexistent")
                         if direct is None else direct)
            upstream = "1.1.1.1" if emergency else "127.0.0.1#5353"
            text = ("port=5352\nlisten-address=%s\nbind-interfaces\nno-resolv\nno-hosts\n"
                    "server=%s\ncache-size=1000\nuser=root\npid-file=/run/dnsmasq-redut-c1.pid\n"
                    % (gateway, upstream)) + whitelist_text(sb)
            unit = ("[Unit]\nDescription=REDUT primary contour client DNS\nAfter=wg-quick@wg0.service\n"
                    "[Service]\nType=simple\nExecStart=/usr/sbin/dnsmasq --keep-in-foreground --conf-file=%s\n"
                    "Restart=on-failure\nRestartSec=5\n[Install]\nWantedBy=multi-user.target\n" % conf_path)
            changed = _write_if_changed(conf_path, text)
            changed_unit = _write_if_changed(unit_path, unit, 0o644)
            if _guard_unit(cfg) or changed_unit:
                contours._run(["systemctl", "daemon-reload"])
            contours._run(["systemctl", "enable", GUARD_SERVICE])
            contours._run(["systemctl", "enable", PRIMARY_SERVICE])
            contours._run(["systemctl", "restart" if changed or restart else "start", PRIMARY_SERVICE])
        primary_firewall(cfg, enabled)
        if not enabled:
            contours._run(["systemctl", "disable", "--now", PRIMARY_SERVICE],
                          allow_failure=not os.path.exists(unit_path))
            # Stopping a required guard would also stop WireGuard. Remove its
            # dependency first; the completed oneshot may remain active.
            unit_dir = os.path.dirname(unit_path)
            guard_path = os.path.join(unit_dir, GUARD_SERVICE + ".service")
            if os.path.exists(guard_path):
                contours._run(["systemctl", "disable", GUARD_SERVICE])
            for filename in (os.path.join(unit_dir, "wg-quick@wg0.service.d", "40-redut-dns.conf"),
                             guard_path, unit_path):
                try:
                    os.unlink(filename)
                except FileNotFoundError:
                    pass
            contours._run(["systemctl", "daemon-reload"])
            try:
                os.unlink(conf_path)
            except FileNotFoundError:
                pass


def primary_rules(cfg, enabled):
    # No reference to the secondary set may survive its deletion.
    second = contours.read(cfg)["secondary"] in ("ready", "creating")
    skip = ["-m set --match-set %s src -j RETURN" % contours.SET] if second else []
    scope = "-i wg0 -s %s" % cfg["subnet"]
    nat = skip + ["%s -p %s --dport 53 -j REDIRECT --to-ports 5352" % (scope, p)
                  for p in ("udp", "tcp")] if enabled else []
    allowed = scope + (" -m set ! --match-set %s src" % contours.SET if second else "")
    acl = ["%s -p %s --dport 5352 -j ACCEPT" % (allowed, p) for p in ("udp", "tcp")]
    acl += ["-p %s --dport 5352 -j REJECT" % p for p in ("udp", "tcp")]
    return [("nat", "PREROUTING", "REDUT_C1_DNS", nat),
            ("filter", "INPUT", "REDUT_C1_DNS_ACL", acl if enabled else [])]


def primary_firewall(cfg, enabled):
    if enabled and contours.read(cfg)["secondary"] in ("ready", "creating"):
        contours._run(["ipset", "create", contours.SET, "hash:ip", "family", "inet", "-exist"])
    for table, parent, chain, rules in primary_rules(cfg, enabled):
        contours._chain(table, chain, rules)
        contours._hook(table, parent, chain)


def boot_guard(cfg):
    """Redirect client DNS before WireGuard starts, even if no core is ready."""
    if managed(apply.load_json(cfg["singbox_config"])):
        primary_firewall(cfg, True)


def boot_guard_proven(cfg):
    if not managed(apply.load_json(cfg["singbox_config"])):
        return True
    for table, parent, chain, rules in primary_rules(cfg, True):
        prefix = ["/usr/sbin/iptables", "-w", "5", "-t", table]
        rc, _ = contours._run(prefix + ["-C", parent, "-j", chain], allow_failure=True)
        if rc:
            return False
        for rule in rules:
            rc, _ = contours._run(prefix + ["-C", chain] + shlex.split(rule), allow_failure=True)
            if rc:
                return False
    return True


def ensure_boot_guard(cfg):
    """Install the durable WG dependency BEFORE the first managed config exists."""
    if contours.secondary(cfg):
        return
    if _guard_unit(cfg):
        contours._run(["systemctl", "daemon-reload"])
    contours._run(["systemctl", "enable", GUARD_SERVICE])


def _guard_unit(cfg):
    unit_dir = cfg.get("_test_unit_dir") or "/etc/systemd/system"
    unit = ("[Unit]\nDescription=REDUT client DNS guard before WireGuard\nDefaultDependencies=no\n"
            "After=local-fs.target\nBefore=network-pre.target wg-quick@wg0.service redut-contours-guard.service\n"
            "Wants=network-pre.target\n[Service]\nType=oneshot\nRemainAfterExit=yes\n"
            "ExecStart=/usr/bin/python3 /opt/vpn-panel/dns_policy.py\n[Install]\nWantedBy=network-pre.target\n")
    changed = _write_if_changed(os.path.join(unit_dir, GUARD_SERVICE + ".service"), unit, 0o644)
    dropin = "[Unit]\nRequires=redut-dns-policy-guard.service\nAfter=redut-dns-policy-guard.service\n"
    changed = _write_if_changed(os.path.join(unit_dir, "wg-quick@wg0.service.d", "40-redut-dns.conf"), dropin, 0o644) or changed
    return changed



def _write_if_changed(path, text, permissions=0o600):
    try:
        with open(path, encoding="utf-8") as handle:
            if handle.read() == text:
                return False
    except FileNotFoundError:
        pass
    contours._private_text(path, text, permissions)
    return True


def resolve(port, name, transport="udp"):
    """Read A answers, including aliases, from the contour's local DNS engine."""
    txid, query = dns_probe._build_query(None, name)
    kind = socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM
    with socket.socket(socket.AF_INET, kind) as client:
        deadline = time.monotonic() + 5
        client.settimeout(5)
        client.connect(("127.0.0.1", port))
        if kind == socket.SOCK_DGRAM:
            client.send(query)
            data = client.recv(4096)
        else:
            client.sendall(struct.pack("!H", len(query)) + query)
            size = struct.unpack("!H", dns_probe._recv_exact(client, 2, deadline))[0]
            if not 12 <= size <= 4096:
                return []
            data = dns_probe._recv_exact(client, size, deadline)
    if len(data) < 12 or data[:2] != query[:2]:
        return []
    _, flags, count, answers, _, _ = struct.unpack("!HHHHHH", data[:12])
    if not flags & 0x8000 or flags & 0x7A0F or count != 1 or answers > 128:
        return []
    question = dns_probe._question_wire(name)
    if data[12:12 + len(question)] != question:
        return []
    offset = 12 + len(question)
    aliases, addresses = {}, {}
    for _ in range(answers):
        owner, offset = dns_probe._read_name(data, offset)
        rtype, rclass, _, length = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        if offset + length > len(data):
            return []
        if rclass == 1 and rtype == 1 and length == 4:
            addresses.setdefault(owner, []).append(socket.inet_ntoa(data[offset:offset + 4]))
        elif rclass == 1 and rtype == 5:
            aliases[owner], _ = dns_probe._read_name(data, offset)
        offset += length
    seen = set()
    while name in aliases and name not in seen:
        seen.add(name)
        name = aliases[name]
    return addresses.get(name, [])


def verify(cfg):
    """Resolve through this core and actually connect using its DNS answer."""
    port = 5355 if contours.secondary(cfg) else 5353
    interface = contours.TUN if contours.secondary(cfg) else "tun0"
    sb = apply.load_json(cfg["singbox_config"])
    if not managed(sb):
        return apply.verify_for(cfg).get("ok", False)
    for host, path in (("api.ipify.org", "/"), ("ipinfo.io", "/ip")):
        answers = []
        for transport in ("udp", "tcp"):
            try:
                result = resolve(port, host, transport)
            except (OSError, ValueError, struct.error, dns_probe.DNSProbeError):
                result = []
            if not result:
                return False
            answers.append(result[0])
        if mode(sb) in ("provider", "provider_strict") and any(ipaddress.ip_address(ip) not in
                ipaddress.ip_network("198.19.128.0/17" if contours.secondary(cfg) else "198.19.0.0/17")
                for ip in answers):
            return False
        rc, body = apply.run_cmd(["curl", "-q", "-4", "-fsS", "--connect-timeout", "5",
                                  "--max-time", "12", "--noproxy", "*", "--interface", interface,
                                  "--resolve", "%s:443:%s" % (host, answers[0]), "https://" + host + path], timeout=15)
        try:
            if rc == 0 and ipaddress.ip_address(body.strip()).is_global:
                return True
        except ValueError:
            pass
    return False


def _restart(cfg):
    if not apply.restart_for(cfg) or not apply.wait_for(cfg):
        raise DNSPolicyError("Не удалось запустить ядро с настройкой DNS")
    reconcile(cfg, _locked=True)
    flush_client_dns(cfg)


def flush_client_dns(cfg):
    """Expire only this contour's old port-53 NAT mappings after a policy change."""
    from webpanel import clients
    registry = contours.read(contours.main_config(cfg))
    wanted = "2" if contours.secondary(cfg) else "1"
    for peer in clients._parse_peers(clients._wg0_text()):
        if registry["assignments"].get(peer.get("pubkey"), "1") != wanted:
            continue
        for address in clients._peer_allowed_ips(peer):
            network = ipaddress.ip_network(address, strict=False)
            if network.version == 4 and network.prefixlen == 32:
                for protocol in ("udp", "tcp"):
                    contours._run(["conntrack", "-D", "-s", str(network.network_address),
                                   "-p", protocol, "--dport", "53"], allow_failure=True)


def _blocked(cfg, pool):
    if os.path.exists(cfg.get("emergency_intent") or "/nonexistent"):
        raise DNSPolicyError("Сначала отключите аварийный прямой выход в этом контуре")
    if pool.dns_state().get("active_scope") or pool.unfinished_dns_operations():
        raise DNSPolicyError("Сначала завершите восстановление DNS Rescue")


def recover(cfg, pool, operation, _locked=False):
    """Interrupted DNS changes revert to the exact before-image, never another exit."""
    with apply._maybe_lock(cfg, _locked):
        ident = operation["id"]
        phase = operation["phase"]
        if phase in ("committed", "rolled_back", "failed"):
            return {"ok": True, "action": "terminal", "operation_id": ident}
        current = apply.file_checksum(cfg["singbox_config"])
        before, after = operation.get("before_checksum"), operation.get("after_checksum")
        if phase in ("planned", "probing"):
            pool.transition_operation(ident, "failed", error="Настройка DNS прервана до применения")
            return {"ok": False, "action": "cancelled", "operation_id": ident}
        if current not in (before, after):
            pool.transition_operation(ident, "failed", error="Конфигурация уже изменена другой операцией")
            return {"ok": False, "action": "superseded", "operation_id": ident}
        if current == after:
            backup = apply.backup_by_checksum(cfg["ring"], before)
            if not backup:
                raise DNSPolicyError("Не найден точный бэкап DNS; восстановление отложено")
            guard_transition(cfg, apply.load_json(backup))
            apply.atomic_copy_replace(backup, cfg["singbox_config"])
        else:
            # A previous recovery may have replaced the file but failed while
            # restarting the core. Reinstall protection before retrying it.
            guard_transition(cfg)
        _restart(cfg)
        if not verify(cfg):
            raise DNSPolicyError("Проверка восстановленного DNS не прошла; восстановление будет повторено")
        pool.transition_operation(ident, "rolled_back", error="Настройка DNS отменена, восстановлен предыдущий режим")
        return {"ok": False, "action": "rolled_back", "operation_id": ident}


def change(cfg, pool, selected, dry_run=False):
    with apply._maybe_lock(cfg, False):
        _blocked(cfg, pool)
        if not status(cfg)["available"]:
            raise DNSPolicyError("Сначала выберите работающий прокси в этом контуре")
        if pool.unfinished_operations():
            raise DNSPolicyError("Другая операция ещё не завершена; дождитесь восстановления")
        path = cfg["singbox_config"]
        old = apply.load_json(path)
        new = prepare(cfg, old, selected)
        staging = path + ".dns-" + uuid.uuid4().hex
        operation = None
        try:
            apply.dump_json_replace(new, staging)
            rc, _ = apply.singbox_check(cfg.get("singbox_bin") or "/usr/local/bin/sing-box", staging)
            if rc:
                raise DNSPolicyError("Ядро отклонило настройку DNS; действующая конфигурация сохранена")
            if dry_run:
                return {"ok": True, "dry_run": True, "mode": selected}
            if new == old:
                reconcile(cfg, _locked=True)
                return dict(status(cfg), ok=verify(cfg), unchanged=True)
            before = apply.file_checksum(path)
            apply.backup_ring(path, cfg["ring"])
            operation = pool.begin_operation("dns-policy", "user", {"mode": selected},
                                             "dns-policy:" + uuid.uuid4().hex, before_checksum=before)
            ident = operation["id"]
            pool.transition_operation(ident, "staged", after_checksum=apply.file_checksum(staging))
            ensure_boot_guard(cfg)
            guard_transition(cfg, new)
            apply.atomic_copy_replace(staging, path)
            pool.transition_operation(ident, "applied")
            _restart(cfg)
            pool.transition_operation(ident, "verifying")
            if not verify(cfg):
                raise DNSPolicyError("DNS или соединение через выбранный прокси не прошли проверку")
            pool.transition_operation(ident, "committed")
            return dict(status(cfg), ok=True)
        except Exception:
            if operation:
                recover(cfg, pool, pool.get_operation(operation_id=operation["id"]), _locked=True)
            raise
        finally:
            if os.path.exists(staging):
                os.unlink(staging)


if __name__ == "__main__":
    import agent
    config = agent.load_config()
    try:
        with apply._maybe_lock(config, False):
            boot_guard(config)
    except apply.LockBusy:
        if not boot_guard_proven(config):
            raise DNSPolicyError("Защита DNS ещё не установлена") from None
