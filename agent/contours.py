"""Two explicit routing domains sharing the node, WireGuard and provider credentials.

The existing domain keeps its paths and policy. Domain 2 owns all of its files,
processes and chains. Every network mutation holds the existing node-wide lock.
"""
import contextvars
import copy
import ipaddress
import json
import os
import re
import shlex
import subprocess
import sys
import time

CURRENT = contextvars.ContextVar("redut_contour", default="1")
TUN = "tun-redut-c2"
ADDRESS = "172.31.255.1/30"
TABLE = "20101"
MARK = "0x65"
PRIORITY = "101"
SERVICE = "sing-box-redut-c2"
DNS_SERVICE = "dnsmasq-redut-c2"
GUARD_SERVICE = "redut-contours-guard"
SET = "redut_c2_peers"
SET6 = "redut_c2_peers6"


class ContourError(ValueError):
    pass


def secondary(cfg):
    return str((cfg or {}).get("contour_id", "1")) == "2"


def ensure_ready(cfg):
    if secondary(cfg) and read(cfg)["secondary"] != "ready":
        raise ContourError("Второй контур недоступен для изменения")


def registry_path(cfg):
    return (cfg or {}).get("contours_path") or os.path.join(
        os.path.dirname((cfg or {}).get("_source") or "/etc/vpn-panel/config.json"), "contours.json")


def read(cfg):
    try:
        with open(registry_path(cfg), encoding="utf-8") as handle:
            value = json.load(handle)
    except FileNotFoundError:
        return {"version": 1, "revision": 0, "secondary": None, "assignments": {}}
    if (not isinstance(value, dict) or value.get("version") != 1
            or not isinstance(value.get("assignments"), dict)
            or value.get("secondary") not in (None, "creating", "ready", "deleting")
            or type(value.get("revision")) is not int or value["revision"] < 0
            or any(not isinstance(k, str) or v != "2" for k, v in value["assignments"].items())
            or (value.get("secondary") is None and value["assignments"])):
        raise ContourError("Повреждено описание контуров; требуется восстановление")
    return value


def write(cfg, registry):
    import apply
    registry["revision"] = int(registry.get("revision", 0)) + 1
    apply.dump_json_replace(registry, registry_path(cfg))


def paths(cfg):
    conf_dir = os.path.join(os.path.dirname(registry_path(cfg)), "contours", "2")
    state_dir = os.path.join(os.path.dirname(cfg["db"]), "contours", "2")
    return {"config": os.path.join(conf_dir, "config.json"),
            "singbox": os.path.join(conf_dir, "sing-box.json"),
            "dnsmasq": os.path.join(conf_dir, "dnsmasq.conf"),
            "db": os.path.join(state_dir, "state.db"), "ring": os.path.join(state_dir, "cfg"),
            "state": state_dir}


def config(main):
    import config_schema
    if read(main)["secondary"] not in ("ready", "creating"):
        raise ContourError("Второй контур ещё не создан")
    path = paths(main)["config"]
    try:
        with open(path, encoding="utf-8") as handle:
            raw = json.load(handle)
    except (OSError, ValueError):
        raise ContourError("Создание второго контура не завершено") from None
    result = config_schema.normalize(raw, source=path)
    if not secondary(result):
        raise ContourError("Неверный идентификатор второго контура")
    return result


def main_config(cfg):
    if not secondary(cfg):
        return cfg
    import agent
    return agent.load_config(cfg["main_config"])


def provider_contours(cfg, secrets):
    """Explicit subscription membership; old installations keep their scope."""
    block = (secrets or {}).get("zenxnet") or {}
    if not isinstance(block, dict) or not block.get("api_key"):
        return ()
    if "contours" not in block:
        return ("1", "2") if read(cfg)["secondary"] else ("1",)
    values = block["contours"]
    if (not isinstance(values, list) or not values
            or any(value not in ("1", "2") for value in values)
            or len(set(values)) != len(values)):
        return ()
    return tuple(values)


def scoped_secrets(cfg, secrets):
    """Select provider credentials without changing node-wide authentication."""
    selected = "2" if secondary(cfg) else "1"
    membership = provider_contours(cfg, secrets)
    return {key: value for key, value in (secrets or {}).items()
            if not (secondary(cfg) and key in ("proxy6", "proxyline", "proxywing"))
            and not (key == "zenxnet" and selected not in membership)}


def allowed_providers(cfg, providers, secrets=None):
    if secondary(cfg):
        providers = {k: v for k, v in providers.items() if k == "zenxnet"}
    if secrets is not None:
        selected = "2" if secondary(cfg) else "1"
        if selected not in provider_contours(cfg, secrets):
            providers = {k: v for k, v in providers.items() if k != "zenxnet"}
    return providers


def _run(args, allow_failure=False, data=None):
    try:
        result = subprocess.run(args, input=data, capture_output=True, text=True, timeout=40)
    except (OSError, subprocess.SubprocessError):
        raise ContourError("Не удалось выполнить операцию контура") from None
    if result.returncode and not allow_failure:
        raise ContourError("Операция контура отклонена: " + os.path.basename(args[0]))
    return result.returncode, result.stdout


def _private_text(path, text, mode=0o600):
    import tempfile
    parent = os.path.dirname(path)
    os.makedirs(parent, mode=0o700, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".redut-c2-", dir=parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def peer_addresses(cfg, registry=None):
    """Resolve saved public-key identities against the current WG configuration."""
    from webpanel import clients
    registry = registry or read(cfg)
    subnet = ipaddress.ip_network(cfg["subnet"], strict=True)
    peers = clients._parse_peers(clients._wg0_text())
    known = {peer.get("pubkey") for peer in peers}
    protected = [peer for peer in peers if registry["assignments"].get(peer.get("pubkey")) == "2"]
    try:
        pending = clients._load_client_operation(cfg)
    except clients.ClientError as error:
        raise ContourError(str(error)) from error
    # A durable revoke may precede live removal. Keep its old source addresses
    # protected until recovery proves that the peer is absent or restored.
    if pending and (registry["assignments"].get(pending["pubkey"]) == "2"
                    or (pending["kind"] == "add" and pending.get("contour") == "2")):
        values = ([pending["address"] + "/32"] if pending["kind"] == "add" else
                  pending.get("rollback_allowed_ips") or [pending["address"] + "/32"])
        protected.append({"allowed_ips_lines": values})
    addresses, addresses6 = [], []
    for peer in protected:
        allowed = clients._peer_allowed_ips(peer)
        if not allowed:
            raise ContourError("Не удалось подтвердить адреса назначенного устройства")
        for value in allowed:
            if not value.strip():
                continue
            network = ipaddress.ip_network(value.strip(), strict=False)
            if network.version == 4:
                if network.prefixlen != 32 or network.network_address not in subnet:
                    raise ContourError("Адрес устройства не принадлежит VPN-подсети")
                addresses.append(str(network.network_address))
            else:
                if network.prefixlen != 128:
                    raise ContourError("Для второго контура требуется отдельный IPv6-адрес устройства")
                addresses6.append(str(network.network_address))
    return sorted(set(addresses)), sorted(set(addresses6)), known


def validate_resources(cfg):
    """Reject collisions before creating or assigning any resource."""
    network = ipaddress.ip_interface(ADDRESS).network
    if network.overlaps(ipaddress.ip_network(cfg["subnet"])):
        raise ContourError("Адрес второго TUN пересекается с WireGuard")
    _, raw = _run(["ip", "-j", "address", "show"])
    for device in json.loads(raw):
        if device["ifname"] == TUN:
            raise ContourError("Интерфейс второго контура уже занят")
        for item in device.get("addr_info", []):
            if item.get("family") == "inet":
                existing = ipaddress.ip_interface("%s/%s" % (item["local"], item["prefixlen"])).network
                if network.overlaps(existing):
                    raise ContourError("Адрес второго TUN пересекается с сетью узла")
    _, rules = _run(["ip", "-4", "rule", "show"])
    if re.search(r"(?m)^\s*101:", rules) or re.search(r"fwmark 0x65(?:\s|/)", rules):
        raise ContourError("Метка или приоритет второго контура уже заняты")
    _, routes = _run(["ip", "route", "show", "table", TABLE], allow_failure=True)
    if routes.strip():
        raise ContourError("Таблица второго контура уже занята")
    for port in (5354, 5355):
        _, sockets = _run(["ss", "-H", "-lntup", "sport", "=", str(port)])
        if sockets.strip():
            raise ContourError("DNS-порт второго контура уже занят")
    unit_dir = cfg.get("_test_unit_dir") or "/etc/systemd/system"
    for service in (SERVICE, DNS_SERVICE, GUARD_SERVICE):
        if os.path.exists(os.path.join(unit_dir, service + ".service")):
            raise ContourError("Служба второго контура уже существует вне реестра")
    for name in (SET, SET6):
        rc, _ = _run(["ipset", "list", name], allow_failure=True)
        if rc == 0:
            raise ContourError("Список адресов второго контура уже занят")
    _, routes = _run(["ip", "-j", "route", "show", "table", "all"])
    for route in json.loads(routes):
        destination = route.get("dst", "default")
        if destination != "default" and network.overlaps(ipaddress.ip_network(destination, strict=False)):
            raise ContourError("Адрес второго TUN пересекается с маршрутом узла")


def create(cfg, secrets, _locked=False):
    import apply
    import pool
    from providers import make_providers
    with apply._maybe_lock(cfg, _locked):
        registry = read(cfg)
        if registry["secondary"] == "ready":
            return {"ok": True, "id": "2", "existing": True}
        if registry["secondary"] == "deleting":
            raise ContourError("Удаление второго контура ещё не завершено")
        subscription = secrets.get("zenxnet") or {}
        if not subscription.get("api_key"):
            raise ContourError("Сначала добавьте подписку ZenXNet")
        if "contours" in subscription and "2" not in provider_contours(cfg, secrets):
            raise ContourError("Сначала подключите подписку ко второму контуру")
        main_pool = pool.Pool(cfg["db"])
        try:
            if main_pool.dns_state().get("phase") not in ("idle", "disabled") or main_pool.unfinished_dns_operations():
                raise ContourError("Сначала завершите активную операцию DNS Rescue")
        finally:
            main_pool.close()
        # Reuse the account's durable cache and HWID. A second contour must
        # never need a temporary copy of its catalog in the primary database.
        provider = make_providers(secrets)["zenxnet"]
        catalog = provider.list()
        if not catalog:
            raise ContourError("Сначала загрузите каталог ZenXNet")
        if not registry["secondary"]:
            validate_resources(cfg)
            registry["secondary"] = "creating"
            write(cfg, registry)
        p = paths(cfg)
        for directory in (os.path.dirname(p["config"]), p["state"], p["ring"]):
            os.makedirs(directory, mode=0o700, exist_ok=True)
        child = copy.deepcopy({k: v for k, v in cfg.items() if not k.startswith("_")})
        child.update(contour_id="2", main_config=cfg["_source"], contours_path=registry_path(cfg),
                     db=p["db"], ring=p["ring"], singbox_config=p["singbox"],
                     boot_script=os.path.join(os.path.dirname(p["config"]), "unused-boot.sh"),
                     emergency_flag=os.path.join(p["state"], "emergency.flag"),
                     emergency_intent=os.path.join(p["state"], "emergency.intent"))
        child["auto_prolong"] = dict(child.get("auto_prolong") or {}, enabled=False,
                                     proxywing_provider_auto_renew=False)
        child["dns_rescue"] = dict(child.get("dns_rescue") or {}, enabled=False, mode="disabled")
        child["update"] = dict(child.get("update") or {}, auto=False)
        if not os.path.exists(p["config"]):
            apply.dump_json_replace(child, p["config"])
        if not os.path.exists(p["singbox"]):
            base = apply.load_json(cfg["singbox_config"])
            base["inbounds"] = [{"type": "tun", "tag": "tun-in", "interface_name": TUN,
                                 "address": [ADDRESS], "auto_route": False},
                                {"type": "direct", "tag": "c2-dns", "listen": "127.0.0.1",
                                 "listen_port": 5355, "override_address": "1.1.1.1", "override_port": 53}]
            base["outbounds"] = [{"type": "direct", "tag": "socks-out"},
                                 {"type": "direct", "tag": "http-tg"}]
            base["route"]["rules"].insert(0, {"inbound": "c2-dns", "action": "hijack-dns"})
            # Keep bootstrap/direct outbounds referenced by the node's DNS rules.
            base["outbounds"].extend(copy.deepcopy(o) for o in apply.load_json(cfg["singbox_config"])["outbounds"]
                                     if o.get("tag") not in ("socks-out", "http-tg"))
            # A new contour has its own DNS cache and starts with public DNS.
            import dns_policy
            base = dns_policy.prepare(child, base, "cloudflare")
            apply.dump_json_replace(base, p["singbox"])
        rc, _ = _run([cfg.get("singbox_bin") or "/usr/local/bin/sing-box", "check", "-c", p["singbox"]], allow_failure=True)
        if rc:
            raise ContourError("Ядро отклонило конфигурацию второго контура")
        second_pool = pool.Pool(p["db"])
        try:
            second_pool.set_setting("zenxnet_auto_admit", "1")
            for row in catalog:
                uid = "%s:%s" % (row["provider"], row["ext_id"])
                second_pool.upsert_proxy(row, role="auto" if not second_pool.get(uid) else None)
            second_pool.set_setting("subscription:zenxnet", json.dumps(provider.metadata))
        finally:
            second_pool.close()
        sync_dns(cfg, restart=False)
        unit_dir = cfg.get("_test_unit_dir") or "/etc/systemd/system"
        unit = ("[Unit]\nDescription=REDUT second contour\nAfter=network-online.target wg-quick@wg0.service\n"
                "[Service]\nType=simple\nExecStart=%s run -c %s\nRestart=on-failure\nRestartSec=5\n"
                "[Install]\nWantedBy=multi-user.target\n" % (cfg.get("singbox_bin") or "/usr/local/bin/sing-box", p["singbox"]))
        dns_unit = ("[Unit]\nDescription=REDUT second contour DNS\nAfter=wg-quick@wg0.service\n"
                    "[Service]\nType=simple\nExecStart=/usr/sbin/dnsmasq --keep-in-foreground --conf-file=%s\n"
                    "Restart=on-failure\nRestartSec=5\n[Install]\nWantedBy=multi-user.target\n" % p["dnsmasq"])
        _private_text(os.path.join(unit_dir, SERVICE + ".service"), unit, 0o644)
        _private_text(os.path.join(unit_dir, DNS_SERVICE + ".service"), dns_unit, 0o644)
        guard_unit = ("[Unit]\nDescription=REDUT contour guard before WireGuard\n"
                      "DefaultDependencies=no\nAfter=local-fs.target\nBefore=network-pre.target wg-quick@wg0.service\n"
                      "Wants=network-pre.target\n[Service]\nType=oneshot\nRemainAfterExit=yes\n"
                      "ExecStart=/usr/bin/python3 /opt/vpn-panel/contours.py --guard-unit\n"
                      "[Install]\nWantedBy=network-pre.target\n")
        _private_text(os.path.join(unit_dir, GUARD_SERVICE + ".service"), guard_unit, 0o644)
        _private_text(os.path.join(unit_dir, "wg-quick@wg0.service.d", "50-redut-contours.conf"),
                      "[Unit]\nRequires=redut-contours-guard.service\nAfter=redut-contours-guard.service\n", 0o644)
        _run(["systemctl", "daemon-reload"])
        _run(["systemctl", "enable", SERVICE, DNS_SERVICE, GUARD_SERVICE])
        _run(["systemctl", "start", DNS_SERVICE])
        registry["secondary"] = "ready"
        write(cfg, registry)
        reconcile_network(cfg, _locked=True)
    if not _locked:
        _run(["systemctl", "start", GUARD_SERVICE])
    return {"ok": True, "id": "2"}


def sync_dns(cfg, restart=True):
    """Private DNS cache follows this contour's exit and current RU exceptions."""
    p = paths(cfg)
    child = config(cfg)
    gateway = str(next(ipaddress.ip_network(cfg["subnet"]).hosts()))
    import apply
    import dns_policy
    live = apply.load_json(child["singbox_config"])
    direct = os.path.exists(child["emergency_intent"]) and not dns_policy.strict(live)
    upstream = "1.1.1.1" if direct else "127.0.0.1#5355"
    dns = ("port=5354\nlisten-address=%s\nbind-interfaces\nno-resolv\nno-hosts\n"
           "server=%s\ncache-size=1000\nuser=root\npid-file=/run/dnsmasq-redut-c2.pid\n" % (gateway, upstream))
    dns += dns_policy.whitelist_text(live)
    try:
        with open(p["dnsmasq"], encoding="utf-8") as handle:
            if handle.read() == dns:
                return
    except FileNotFoundError:
        pass
    _private_text(p["dnsmasq"], dns)
    if restart:
        _run(["systemctl", "restart", DNS_SERVICE])


def verify_dns(cfg):
    """Exercise UDP and TCP upstream DNS through the second sing-box instance."""
    import socket
    import struct
    query_id = os.urandom(2)
    query = query_id + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x03www\x07example\x03com\x00\x00\x01\x00\x01"
    try:
        for transport in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
            with socket.socket(socket.AF_INET, transport) as client:
                client.settimeout(8)
                client.connect(("127.0.0.1", 5355))
                if transport == socket.SOCK_DGRAM:
                    client.send(query)
                    response = client.recv(4096)
                else:
                    client.sendall(struct.pack("!H", len(query)) + query)
                    length = b""
                    while len(length) < 2:
                        part = client.recv(2 - len(length))
                        if not part: raise OSError("EOF")
                        length += part
                    size = struct.unpack("!H", length)[0]
                    response = b""
                    while len(response) < size:
                        part = client.recv(size - len(response))
                        if not part: raise OSError("EOF")
                        response += part
                if len(response) < 12 or response[:2] != query_id or response[3] & 15 or response[6:8] == b"\0\0":
                    return False
        return True
    except (OSError, ValueError):
        return False


def _ipset_swap(name, addresses, family):
    _run(["ipset", "create", name, "hash:ip", "family", family, "-exist"])
    temporary = name + "_next"
    _run(["ipset", "create", temporary, "hash:ip", "family", family, "-exist"])
    _run(["ipset", "flush", temporary])
    for address in addresses:
        _run(["ipset", "add", temporary, address])
    _run(["ipset", "swap", temporary, name])
    _run(["ipset", "destroy", temporary])


def _chain(table, name, rules, ipv6=False):
    binary = "ip6tables-restore" if ipv6 else "iptables-restore"
    data = "*%s\n:%s - [0:0]\n-F %s\n" % (table, name, name)
    data += "".join("-A %s %s\n" % (name, rule) for rule in rules) + "COMMIT\n"
    _run([binary, "--wait", "5", "--noflush"], data=data)


def _hook(table, parent, name, position=1, ipv6=False):
    binary = "ip6tables" if ipv6 else "/usr/sbin/iptables"
    prefix = [binary, "-w", "5", "-t", table]
    rc, _ = _run(prefix + ["-C", parent, "-j", name], allow_failure=True)
    if rc:
        _run(prefix + ["-I", parent, str(position), "-j", name])


def _place_hook(table, parent, name, position=1, existing=None):
    """Move our jump without an interval in which its protection is absent."""
    prefix = ["/usr/sbin/iptables", "-w", "5", "-t", table]
    if existing is None:
        _, existing = _run(prefix + ["-S", parent])
    lines = [line for line in existing.splitlines() if line.startswith("-A " + parent + " ")]
    target = "-A %s -j %s" % (parent, name)
    ordinary = [(i + 1, line) for i, line in enumerate(lines) if line != target]
    desired = min(max(1, position), len(ordinary) + 1)
    expected = [line for _, line in ordinary]
    expected.insert(desired - 1, target)
    if lines == expected:
        return
    insertion = ordinary[desired - 1][0] if desired <= len(ordinary) else len(lines) + 1
    _run(prefix + ["-I", parent, str(insertion), "-j", name])
    # Delete original copies by descending position after accounting for the
    # newly inserted jump. Keeping one copy throughout also handles upgrades.
    old = [i + 1 for i, line in enumerate(lines) if line == target]
    for index in reversed(old):
        _run(prefix + ["-D", parent, str(index + (index >= insertion))])


def _input_acl(strict=False):
    rules = [rule for protocol in ("udp", "tcp") for rule in (
        "-i wg0 -m set --match-set %s src -p %s --dport 5354 -j ACCEPT" % (SET, protocol),
        "-p %s --dport 5354 -j REJECT" % protocol,
        "-i wg0 -m set --match-set %s src -p %s --dport 53 -j REJECT" % (SET, protocol))]
    import dns_policy
    port = dns_policy.STRICT_PROXY_PORT
    if strict:
        rules += ["-i wg0 -m set --match-set %s src -p tcp --dport %s -j ACCEPT" % (SET, port)]
    # A stale core from a failed mode change must not expose its proxy listener.
    rules += ["-p tcp --dport %s -j REJECT" % port]
    return rules


def strict_transition_guard(cfg):
    """Close contour 2 while its durable policy changes; caller holds the lock."""
    if not secondary(cfg):
        raise ContourError("Строгий режим доступен только во втором контуре")
    ensure_ready(cfg)
    main = main_config(cfg)
    ips, _, _ = peer_addresses(main)
    _ipset_swap(SET, ips, "inet")
    _chain("filter", "REDUT_C2_GUARD", [
        "-i wg0 -m set --match-set %s src -j REJECT" % SET])
    _place_hook("filter", "FORWARD", "REDUT_C2_GUARD")
    _chain("filter", "REDUT_C2_DNS_ACL", _input_acl(False))
    _place_hook("filter", "INPUT", "REDUT_C2_DNS_ACL")


def _empty_lifecycle(registry, ips, ips6):
    """An unfinished, unused contour must not prevent the primary from booting."""
    return (registry["secondary"] in ("creating", "deleting")
            and not registry["assignments"] and not ips and not ips6)


def reconcile_network(cfg, _locked=False):
    import apply
    import dns_policy
    cfg = main_config(cfg)
    with apply._maybe_lock(cfg, _locked):
        registry = read(cfg)
        if not registry["secondary"]:
            import dns_policy
            dns_policy.reconcile(cfg, _locked=True)
            return
        if registry["secondary"] == "deleting":
            return
        if registry["secondary"] == "creating":
            ips, ips6, _ = peer_addresses(cfg, registry)
            if _empty_lifecycle(registry, ips, ips6):
                # The durable intent may precede the child files. Lifecycle
                # recovery will finish them; primary boot can proceed now.
                dns_policy.reconcile(cfg, _locked=True)
                return
        child = config(cfg)
        live = apply.load_json(child["singbox_config"])
        strict = dns_policy.strict(live)
        ips, ips6, _ = peer_addresses(cfg, registry)
        _, saved_set = _run(["ipset", "save", SET], allow_failure=True)
        previous_ips = {line.split()[2] for line in saved_set.splitlines()
                        if line.startswith("add " + SET + " ") and len(line.split()) >= 3}
        if strict:
            # Install the source guard before replacing any stale direct route.
            _ipset_swap(SET, ips, "inet")
            _chain("filter", "REDUT_C2_GUARD", [
                "-i wg0 -m set --match-set %s src ! -o %s -j REJECT" % (SET, TUN)])
            _place_hook("filter", "FORWARD", "REDUT_C2_GUARD")
        # A permanent unreachable fallback prevents rule/table/TUN loss from
        # silently sending assigned clients through the main WAN route.
        _run(["ip", "route", "replace", "unreachable", "default", "metric", "32760", "table", TABLE])
        _run(["ip", "route", "replace", cfg["subnet"], "dev", "wg0", "table", TABLE])
        _, rules = _run(["ip", "-4", "rule", "show"])
        expected = re.compile(r"(?m)^101:\s+from all fwmark 0x65 lookup 20101\s*$")
        if not expected.search(rules):
            if re.search(r"(?m)^101:", rules):
                raise ContourError("Приоритет второго контура занят другим правилом")
            _run(["ip", "-4", "rule", "add", "priority", PRIORITY, "fwmark", MARK, "lookup", TABLE])
        direct = os.path.exists(child["emergency_intent"]) and not strict
        configured = any(o.get("tag") == "socks-out" and o.get("type") in ("vless", "socks", "http")
                         for o in live.get("outbounds", []))
        carrier = os.path.exists("/sys/class/net/" + TUN)
        if direct:
            _run(["ip", "route", "replace", "default", "via", cfg["gw"], "dev", cfg["wan"],
                  "metric", "100", "table", TABLE])
        elif carrier and configured:
            _run(["ip", "route", "replace", "default", "dev", TUN, "metric", "100", "table", TABLE])
        else:
            _run(["ip", "route", "del", "default", "metric", "100", "table", TABLE], allow_failure=True)
        if carrier:
            _run(["sysctl", "-q", "net.ipv4.conf.%s.rp_filter=0" % TUN])
        if not strict:
            _ipset_swap(SET, ips, "inet")
        _ipset_swap(SET6, ips6, "inet6")
        _chain("mangle", "REDUT_C2", ["-m set --match-set %s src -j MARK --set-mark %s" % (SET, MARK),
                                      "-m set --match-set %s src -j ACCEPT" % SET])
        _, parent = _run(["/usr/sbin/iptables", "-t", "mangle", "-S", "REDUT_PREROUTING"])
        lines = [line for line in parent.splitlines() if line.startswith("-A ")
                 and line != "-A REDUT_PREROUTING -j REDUT_C2"]
        index = next((i + 1 for i, line in enumerate(lines) if "-j MARK" in line), None)
        if index is None:
            raise ContourError("Не найдена штатная маркировка основного контура")
        _place_hook("mangle", "REDUT_PREROUTING", "REDUT_C2", 1 if strict else index, existing=parent)
        _chain("nat", "REDUT_C2_DNS", ["-i wg0 -m set --match-set %s src -p %s --dport 53 -j REDIRECT --to-ports 5354" % (SET, proto)
                                       for proto in ("udp", "tcp")])
        _hook("nat", "PREROUTING", "REDUT_C2_DNS")
        permitted = cfg["wan"] if direct else TUN
        guard = []
        if not strict:
            guard += ["-i wg0 -m set --match-set %s src -m set --match-set %s dst -j RETURN" % (SET, allowed)
                      for allowed in ("ru_whitelist", "ru_whitelist_net")]
            guard += ["-i wg0 -m set --match-set %s src -d %s -j RETURN" % (SET, cfg["subnet"])]
        guard += ["-i wg0 -m set --match-set %s src ! -o %s -j REJECT" % (SET, permitted)]
        _chain("filter", "REDUT_C2_GUARD", guard)
        _hook("filter", "FORWARD", "REDUT_C2_GUARD")
        _chain("filter", "REDUT_C2_DNS_ACL", _input_acl(strict))
        if strict:
            _place_hook("filter", "INPUT", "REDUT_C2_DNS_ACL")
        else:
            _hook("filter", "INPUT", "REDUT_C2_DNS_ACL")
        _chain("filter", "REDUT_C2_V6", ["-i wg0 -m set --match-set %s src -j REJECT" % SET6], ipv6=True)
        _hook("filter", "FORWARD", "REDUT_C2_V6", ipv6=True)
        _hook("filter", "INPUT", "REDUT_C2_V6", ipv6=True)
        for address in previous_ips.symmetric_difference(ips):
            # Expire only DNS flows for devices whose assignment changed.
            # Other clients and established non-DNS sessions stay untouched.
            for protocol in ("udp", "tcp"):
                _run(["conntrack", "-D", "-s", address, "-p", protocol, "--dport", "53"], allow_failure=True)
        sync_dns(cfg)
        import dns_policy
        dns_policy.reconcile(cfg, _locked=True)


def boot_guard(cfg, _locked=False):
    """Install the source-based guard before WG can accept assigned devices."""
    import apply
    with apply._maybe_lock(cfg, _locked):
        import dns_policy
        dns_policy.boot_guard(cfg)
        registry = read(cfg)
        if not registry["secondary"]:
            return
        ips, ips6, _ = peer_addresses(cfg, registry)
        strict = (False if _empty_lifecycle(registry, ips, ips6) else
                  dns_policy.strict(apply.load_json(paths(cfg)["singbox"])))
        _ipset_swap(SET, ips, "inet")
        _ipset_swap(SET6, ips6, "inet6")
        _chain("filter", "REDUT_C2_GUARD", ["-i wg0 -m set --match-set %s src ! -o %s -j REJECT" % (SET, TUN)])
        _place_hook("filter", "FORWARD", "REDUT_C2_GUARD")
        _chain("filter", "REDUT_C2_DNS_ACL", _input_acl(strict))
        _place_hook("filter", "INPUT", "REDUT_C2_DNS_ACL")
        _chain("filter", "REDUT_C2_V6", ["-i wg0 -m set --match-set %s src -j REJECT" % SET6], ipv6=True)
        _hook("filter", "FORWARD", "REDUT_C2_V6", ipv6=True)
        _hook("filter", "INPUT", "REDUT_C2_V6", ipv6=True)


def boot_guard_proven(cfg):
    """Only the strict, already-installed boot guard can satisfy a busy unit.

    The installer installs this guard with its inherited lock before starting
    WireGuard. systemd cannot inherit that lock; its unit performs no writes
    when another process owns it and checks the kernel protection instead.
    """
    registry = read(cfg)
    ips, ips6, _ = peer_addresses(cfg, registry)
    if not registry["secondary"]:
        return read(cfg) == registry
    for name, expected in ((SET, ips), (SET6, ips6)):
        rc, saved = _run(["ipset", "save", name], allow_failure=True)
        members = {line.split()[2] for line in saved.splitlines()
                   if line.startswith("add " + name + " ") and len(line.split()) >= 3}
        if rc or set(expected) != members or (" family " + ("inet6" if name == SET6 else "inet") + " ") not in saved.replace("\n", " ") + " ":
            return False
    import apply
    import dns_policy
    strict = (False if _empty_lifecycle(registry, ips, ips6) else
              dns_policy.strict(apply.load_json(paths(cfg)["singbox"])))
    acl = _input_acl(strict)
    checks = [("/usr/sbin/iptables", "FORWARD", "REDUT_C2_GUARD", [
                  "-i wg0 -m set --match-set %s src ! -o %s -j REJECT" % (SET, TUN)]),
              ("/usr/sbin/iptables", "INPUT", "REDUT_C2_DNS_ACL", acl),
              ("ip6tables", "FORWARD", "REDUT_C2_V6", ["-i wg0 -m set --match-set %s src -j REJECT" % SET6]),
              ("ip6tables", "INPUT", "REDUT_C2_V6", ["-i wg0 -m set --match-set %s src -j REJECT" % SET6])]
    for binary, parent, chain, rules in checks:
        rc, top = _run([binary, "-w", "5", "-t", "filter", "-S", parent], allow_failure=True)
        first = next((line for line in top.splitlines() if line.startswith("-A ")), "")
        if rc or first != "-A %s -j %s" % (parent, chain):
            return False
        rc, existing = _run([binary, "-w", "5", "-t", "filter", "-S", chain], allow_failure=True)
        if rc or len([line for line in existing.splitlines() if line.startswith("-A ")]) != len(rules):
            return False
        for rule in rules:
            rc, _ = _run([binary, "-w", "5", "-t", "filter", "-C", chain] + shlex.split(rule), allow_failure=True)
            if rc:
                return False
    return read(cfg) == registry


def guard_service(cfg):
    import apply
    try:
        boot_guard(cfg)
    except apply.LockBusy:
        if not boot_guard_proven(cfg):
            raise ContourError("Общий lock занят, защита второго контура ещё не подтверждена") from None


def assign(cfg, public_key, target, _locked=False):
    import apply
    import pool
    with apply._maybe_lock(cfg, _locked):
        registry = read(cfg)
        if target not in ("1", "2") or registry["secondary"] != "ready":
            raise ContourError("Контур недоступен")
        _, _, known = peer_addresses(cfg, registry)
        if public_key not in known:
            raise ContourError("Устройство больше не существует")
        if registry["assignments"].get(public_key, "1") == target:
            return {"ok": True, "contour": target, "existing": True}
        target_cfg = config(cfg) if target == "2" else cfg
        verified = apply.verify_for(target_cfg)
        if not verified.get("ok"):
            raise ContourError("Выход выбранного контура не прошёл проверку")
        database = pool.Pool(cfg["db"])
        try:
            if database.dns_state().get("phase") != "idle" or database.unfinished_dns_operations():
                raise ContourError("Сначала завершите активную операцию DNS Rescue")
        finally:
            database.close()
        if target == "2":
            rc, state = _run(["systemctl", "is-active", GUARD_SERVICE], allow_failure=True)
            if rc or state.strip() != "active":
                raise ContourError("Защита второго контура ещё не готова; повторите через минуту")
            rc, state = _run(["systemctl", "is-active", DNS_SERVICE], allow_failure=True)
            if rc or state.strip() != "active" or not verify_dns(target_cfg):
                raise ContourError("DNS второго контура не готов")
            registry["assignments"][public_key] = "2"
        else:
            registry["assignments"].pop(public_key, None)
        previous = read(cfg)
        write(cfg, registry)
        try:
            reconcile_network(cfg, _locked=True)
        except Exception:
            previous["revision"] = registry["revision"]
            write(cfg, previous)
            reconcile_network(cfg, _locked=True)
            raise
        return {"ok": True, "contour": target}


def delete(cfg, _locked=False):
    import apply
    with apply._maybe_lock(cfg, _locked):
        registry = read(cfg)
        if not registry["secondary"]:
            return {"ok": True}
        from webpanel import clients
        try:
            pending = clients._load_client_operation(cfg)
        except clients.ClientError as error:
            raise ContourError(str(error)) from error
        if pending is not None:
            raise ContourError("Сначала завершите восстановление выдачи или отзыва доступа")
        if registry["assignments"]:
            raise ContourError("Сначала перенесите устройства в основной контур")
        registry["secondary"] = "deleting"
        write(cfg, registry)
        _run(["systemctl", "disable", "--now", SERVICE, DNS_SERVICE])
        for table, parent, name, ipv6 in (("mangle", "REDUT_PREROUTING", "REDUT_C2", False),
                ("nat", "PREROUTING", "REDUT_C2_DNS", False),
                ("filter", "INPUT", "REDUT_C2_DNS_ACL", False),
                ("filter", "FORWARD", "REDUT_C2_GUARD", False),
                ("filter", "FORWARD", "REDUT_C2_V6", True), ("filter", "INPUT", "REDUT_C2_V6", True)):
            binary = "ip6tables" if ipv6 else "/usr/sbin/iptables"
            _run([binary, "-w", "5", "-t", table, "-D", parent, "-j", name], allow_failure=True)
            _run([binary, "-w", "5", "-t", table, "-F", name], allow_failure=True)
            _run([binary, "-w", "5", "-t", table, "-X", name], allow_failure=True)
        _run(["ip", "-4", "rule", "del", "priority", PRIORITY, "fwmark", MARK, "lookup", TABLE], allow_failure=True)
        _run(["ip", "route", "flush", "table", TABLE])
        import dns_policy
        dns_policy.reconcile(cfg, _locked=True)
        for name in (SET, SET6):
            _run(["ipset", "destroy", name], allow_failure=True)
        _, rules = _run(["ip", "-4", "rule", "show"])
        if re.search(r"(?m)^101:", rules):
            raise ContourError("Удаление правила второго контура не подтверждено")
        for binary, table, name in (("iptables", "mangle", "REDUT_C2"),
                ("iptables", "nat", "REDUT_C2_DNS"), ("iptables", "filter", "REDUT_C2_GUARD"),
                ("iptables", "filter", "REDUT_C2_DNS_ACL"), ("ip6tables", "filter", "REDUT_C2_V6")):
            rc, remaining = _run([binary, "-t", table, "-S", name], allow_failure=True)
            if rc == 0 and remaining.strip():
                raise ContourError("Удаление сетевых правил ещё не завершено")
        unit_dir = cfg.get("_test_unit_dir") or "/etc/systemd/system"
        try:
            os.unlink(os.path.join(unit_dir, "wg-quick@wg0.service.d", "50-redut-contours.conf"))
        except FileNotFoundError:
            pass
        # Do not stop the guard: systemd Requires would also stop WireGuard.
        _run(["systemctl", "disable", GUARD_SERVICE])
        for service in (SERVICE, DNS_SERVICE, GUARD_SERVICE):
            try:
                os.unlink(os.path.join(unit_dir, service + ".service"))
            except FileNotFoundError:
                pass
        _run(["systemctl", "daemon-reload"])
        # Archive history privately; re-creation starts with empty assignments
        # and without an old emergency intent or manual pin.
        p = paths(cfg)
        suffix = ".deleted-" + str(time.time_ns())
        for directory in (os.path.dirname(p["config"]), p["state"]):
            if os.path.exists(directory):
                os.rename(directory, directory + suffix)
        registry["secondary"] = None
        write(cfg, registry)
        return {"ok": True}


def health(cfg, direct=False):
    import apply
    rc, state = apply.run_cmd(["systemctl", "is-active", SERVICE])
    carrier = os.path.exists("/sys/class/net/" + TUN)
    code, route = apply.run_cmd(["ip", "-4", "route", "get", "8.8.8.8", "mark", MARK])
    dev = cfg["wan"] if direct else TUN
    route_ok = code == 0 and "dev %s " % dev in route + " " and "table %s" % TABLE in route
    return {"active": rc == 0 and state.strip() == "active", "tun0": carrier,
            "route_ok": route_ok, "policy_ok": route_ok, "policy_count": 1 if route_ok else 0,
            "marked_route_ok": route_ok, "ok": rc == 0 and carrier and route_ok}


def emergency(cfg, on, log=print):
    import apply
    ensure_ready(cfg)
    import dns_policy
    if on and dns_policy.strict(apply.load_json(cfg["singbox_config"])):
        log("Строгий режим провайдера запрещает прямой аварийный выход")
        return False
    intent = cfg["emergency_intent"]
    was_direct = os.path.exists(intent)
    if on:
        _private_text(intent, "direct\n")
        _private_text(cfg["emergency_flag"], "direct\n")
    else:
        for path in (intent, cfg["emergency_flag"]):
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
    try:
        reconcile_network(cfg, _locked=True)
        if not health(cfg, direct=on)["route_ok"]:
            raise ContourError("Маршрут второго контура не подтверждён")
        return True
    except Exception:
        if was_direct:
            _private_text(intent, "direct\n")
            _private_text(cfg["emergency_flag"], "direct\n")
        else:
            for path in (intent, cfg["emergency_flag"]):
                try: os.unlink(path)
                except FileNotFoundError: pass
        reconcile_network(cfg, _locked=True)
        return False


def public(cfg):
    registry = read(cfg)
    result = {"contours": [{"id": "1", "name": "Основной", "color": "default"}],
              "can_create": registry["secondary"] is None, "revision": registry["revision"],
              "assignments": registry["assignments"]}
    if registry["secondary"]:
        result["contours"].append({"id": "2", "name": "2 контур", "color": "violet",
                                  "state": registry["secondary"]})
    return result


def scope_conflicts(cfg, scope):
    if secondary(cfg):
        return True
    registry = read(cfg)
    if not registry["assignments"]:
        return False
    addresses, _, _ = peer_addresses(cfg, registry)
    return scope == "all" or scope.removeprefix("peer:") in addresses


def runtime_tick(cfg, secrets):
    """Timer/boot entry: recover lifecycle and run the usual agent in domain 2."""
    import apply
    registry = read(cfg)
    if registry["secondary"] == "creating":
        create(cfg, secrets)
    elif registry["secondary"] == "deleting":
        delete(cfg)
        return
    elif not registry["secondary"]:
        import dns_policy
        dns_policy.reconcile(cfg)
        return
    # Retry a guard start interrupted after durable creation, outside the lock.
    _run(["systemctl", "start", GUARD_SERVICE])
    reconcile_network(cfg)
    child = config(cfg)
    import agent
    import pool
    from providers import make_providers
    from types import SimpleNamespace
    database = pool.Pool(child["db"])
    try:
        last = float(database.get_setting("contour_catalog_refreshed", "0"))
        if time.time() - last >= 1800:
            provider = make_providers(scoped_secrets(child, secrets)).get("zenxnet")
            if provider:
                live = apply.load_json(child["singbox_config"])
                refreshed = database.refresh({"zenxnet": provider}, actor="auto",
                                             keep_hosts={apply.current_upstream(live)})
                if not refreshed["errors"]:
                    database.set_setting("contour_catalog_refreshed", str(time.time()))
                    database.set_setting("subscription:zenxnet", json.dumps(provider.metadata))
    finally:
        database.close()
    agent.cmd_rotate(child, SimpleNamespace(reason="watchdog", force=False))


def sync_membership(cfg):
    """Called under the WG/network lock before reusing addresses and after revoke."""
    main = main_config(cfg)
    registry = read(main)
    if registry["secondary"]:
        _, _, known = peer_addresses(main, registry)
        assignments = {key: value for key, value in registry["assignments"].items() if key in known}
        if assignments != registry["assignments"]:
            registry["assignments"] = assignments
            write(main, registry)
        reconcile_network(main, _locked=True)


if __name__ == "__main__":
    # Boot calls this while holding the existing inherited descriptor.
    import agent
    cfg = agent.load_config()
    held = False
    fd = os.environ.get("REDUT_LOCK_FD", "")
    if os.environ.get("REDUT_LOCK_HELD") == "1" and fd.isdigit():
        import fcntl
        if os.readlink("/proc/self/fd/" + fd) == cfg.get("lock", "/run/vpn-agent.lock"):
            fcntl.flock(int(fd), fcntl.LOCK_EX | fcntl.LOCK_NB)
            held = True
    if "--guard-unit" in sys.argv[1:]:
        guard_service(cfg)
    elif "--guard-only" in sys.argv[1:]:
        boot_guard(cfg, _locked=held)
    else:
        reconcile_network(cfg, _locked=held)
