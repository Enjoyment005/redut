# -*- coding: utf-8 -*-
"""Управление клиентскими WireGuard-конфигами прямо из панели (панель работает от root).

Список / создать / удалить / скачать / QR. Пиры живут в /etc/wireguard/wg0.conf (правим
файл, сохраняя структуру и комментарии-имена — БЕЗ `wg-quick save`, он бы затёр PostUp и
имена), применяем на живом интерфейсе через `wg set` (без разрыва других клиентов).
Полный клиентский `.conf` (с приватником — его нет в wg0.conf) храним в
/etc/wireguard/clients/<name>.conf (0600) — источник для скачивания/QR.
"""
import ipaddress
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile

import apply as apply_mod

WG_CONF = "/etc/wireguard/wg0.conf"
CLIENTS_DIR = "/etc/wireguard/clients"
SRV_PUB = "/etc/wireguard/server_public.key"
NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
CLIENT_OP_MARK = "/var/lib/vpn-panel/wg-client-operation.json"
DNS_OWNED_PHASES = ("probing", "active_isolated", "active_proxy",
                    "active_direct", "recovering")


class ClientError(Exception):
    pass


def _run(args, inp=None, timeout=20):
    try:
        p = subprocess.run(
            args, capture_output=True, text=True, input=inp, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise ClientError("команда WireGuard превысила таймаут")
    except (OSError, subprocess.SubprocessError) as error:
        raise ClientError(str(error))
    if p.returncode != 0:
        raise ClientError((p.stderr or p.stdout or "команда не удалась").strip())
    return p.stdout


def valid_name(name):
    return bool(NAME_RE.match(name or ""))


# ─────────────────────────── параметры сервера ──────────────────────────
def _wg0_text():
    try:
        with open(WG_CONF, encoding="utf-8") as f:
            return f.read()
    except OSError:
        raise ClientError("нет %s" % WG_CONF)


def _listen_port(text):
    m = re.search(r"(?im)^\s*ListenPort\s*=\s*(\d+)", text)
    return int(m.group(1)) if m else 51820


def _server_pubkey(text):
    if os.path.isfile(SRV_PUB):
        with open(SRV_PUB, encoding="utf-8") as f:
            k = f.read().strip()
        if k:
            return k
    m = re.search(r"(?im)^\s*PrivateKey\s*=\s*(\S+)", text)
    if m:
        return _run(["wg", "pubkey"], inp=m.group(1) + "\n").strip()
    raise ClientError("не найден серверный ключ")


def _detect_wan_ip():
    try:
        out = _run(["ip", "-4", "-o", "addr", "show", "scope", "global"])
    except ClientError:
        return ""
    m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", out)
    return m.group(1) if m else ""


def server_params(cfg):
    text = _wg0_text()
    subnet = cfg.get("subnet") or "10.8.0.0/24"
    net = ipaddress.ip_network(subnet, strict=False)
    wg_ip = str(net.network_address + 1)
    port = int(cfg.get("wg_port") or _listen_port(text))
    host = cfg.get("server_ip") or _detect_wan_ip()
    dns = cfg.get("dns") or (wg_ip if cfg.get("has_dnsmasq") else "1.1.1.1")
    return {"text": text, "subnet": subnet, "net": net, "wg_ip": wg_ip,
            "port": port, "host": host, "dns": dns, "server_pub": _server_pubkey(text)}


# ─────────────────────────── разбор пиров wg0.conf ──────────────────────
def _parse_peers(text):
    """-> список пиров [{name, pubkey, psk, allowed_ips}]. Имя = первый '# ...' в блоке [Peer]."""
    peers = []
    for body in re.split(r"(?im)^\s*\[Peer\]\s*$", text)[1:]:
        pub = re.search(r"(?im)^\s*PublicKey\s*=\s*(\S+)", body)
        allowed_lines = [item.strip() for item in re.findall(
            r"(?im)^\s*AllowedIPs\s*=\s*([^\r\n#]*?)\s*$", body)]
        psk = re.search(r"(?im)^\s*PresharedKey\s*=\s*(\S+)", body)
        nm = re.search(r"(?m)^\s*#\s*(.+?)\s*$", body)
        peers.append({"name": nm.group(1).strip() if nm else None,
                      "pubkey": pub.group(1) if pub else None,
                      "psk": psk.group(1) if psk else None,
                      "allowed_ips": allowed_lines[0]
                      if len(allowed_lines) == 1 else None,
                      "allowed_ips_lines": allowed_lines})
    return peers


def _wg_dump():
    """pubkey -> {handshake_unix, rx, tx, endpoint} с живого интерфейса."""
    out = {}
    try:
        raw = _run(["wg", "show", "wg0", "dump"])
    except ClientError:
        return out
    for line in raw.splitlines()[1:]:               # первая строка — сам интерфейс
        f = line.split("\t")
        if len(f) >= 6:
            out[f[0]] = {"endpoint": f[2], "handshake": int(f[4] or 0),
                         "rx": int(f[5] or 0) if len(f) > 5 else 0,
                         "tx": int(f[6] or 0) if len(f) > 6 else 0}
    return out


def list_clients(cfg):
    p = server_params(cfg)
    dump = _wg_dump()
    out = []
    for peer in _parse_peers(p["text"]):
        ip = ""
        try:
            subnet = ipaddress.ip_network(cfg.get("subnet") or "10.8.0.0/24",
                                           strict=False)
            addresses = [ipaddress.ip_network(value, strict=False)
                         for value in _peer_allowed_ips(peer)]
            matches = [network for network in addresses
                       if network.version == 4 and network.prefixlen == 32
                       and network.subnet_of(subnet)]
            if len(matches) == 1:
                ip = str(matches[0].network_address)
        except (ClientError, ValueError):
            pass
        unsupported_reason = ""
        try:
            _exact_peer_ipv4(cfg, peer)
        except ClientError as error:
            unsupported_reason = str(error)
        d = dump.get(peer["pubkey"] or "", {})
        name = peer["name"]
        try:
            conf_name = _stored_conf_for_peer(peer)
        except ClientError as error:
            conf_name = None
            unsupported_reason = "; ".join(
                item for item in (unsupported_reason, str(error)) if item)
        # An unnamed legacy peer may list IPv6 first or use multiple lines.
        # Bind its saved profile by exact peer membership, not display order.
        if not name and conf_name:
            name = conf_name
        out.append({"name": name or ("peer-" + ip.replace(".", "-") if ip else "peer"),
                    "ip": ip, "pubkey": peer["pubkey"],
                    "handshake": d.get("handshake", 0), "rx": d.get("rx", 0),
                    "tx": d.get("tx", 0), "has_conf": bool(conf_name),
                    "conf_name": conf_name,
                    "unsupported": bool(unsupported_reason),
                    "unsupported_reason": unsupported_reason})
    return out


def _stored_ip(name):
    try:
        with open(os.path.join(CLIENTS_DIR, name + ".conf"), encoding="utf-8") as f:
            m = re.search(r"(?im)^\s*Address\s*=\s*(\d+\.\d+\.\d+\.\d+)", f.read())
            return m.group(1) if m else ""
    except OSError:
        return ""


def _used_ips(cfg, peers, net):
    used = {str(net.network_address + 1)}       # .1 сервер
    for peer in peers:
        if not peer.get("pubkey"):
            raise ClientError("существующий peer не содержит PublicKey")
        address = _exact_peer_ipv4(cfg, peer)
        if address in used:
            raise ClientError("WireGuard peer IPv4 пересекаются или дублируются")
        used.add(address)
    return used


def _normalise_allowed_ips(values):
    """Validate a non-empty WireGuard AllowedIPs collection for exact restore."""
    out = []
    for value in values or ():
        try:
            out.append(str(ipaddress.ip_network(str(value).strip(), strict=False)))
        except ValueError as error:
            raise ClientError("peer AllowedIPs имеет неверный формат") from error
    if not out:
        raise ClientError("peer не содержит AllowedIPs для безопасного отката")
    if len(set(out)) != len(out):
        raise ClientError("peer AllowedIPs содержит дубликаты")
    return out


def _peer_allowed_ips(target):
    lines = (target or {}).get("allowed_ips_lines")
    if lines is None:
        lines = [(target or {}).get("allowed_ips") or ""]
    values = [item.strip() for line in lines for item in str(line).split(",")
              if item.strip()]
    return _normalise_allowed_ips(values)


def _set_live_peer_allowed_ips(pubkey, psk, allowed_ips):
    command = ["wg", "set", "wg0", "peer", pubkey]
    pskfile = None
    try:
        if psk:
            with tempfile.NamedTemporaryFile(
                    "w", delete=False,
                    dir="/dev/shm" if os.path.isdir("/dev/shm") else None) as handle:
                handle.write(psk + "\n")
                pskfile = handle.name
            command.extend(["preshared-key", pskfile])
        command.extend(["allowed-ips", ",".join(_normalise_allowed_ips(allowed_ips))])
        _run(command)
    finally:
        if pskfile:
            try:
                os.remove(pskfile)
            except OSError:
                pass


def _set_live_peer(pubkey, psk, address):
    _set_live_peer_allowed_ips(pubkey, psk, [address + "/32"])


def _live_peer_allowed_ips_match(pubkey, allowed_ips):
    output = _run(["wg", "show", "wg0", "allowed-ips"])
    expected = set(_normalise_allowed_ips(allowed_ips))
    for line in output.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0] == pubkey:
            try:
                actual = set(_normalise_allowed_ips(parts[1].split(",")))
            except ClientError:
                return False
            return actual == expected
    return False


def _live_peer_matches(pubkey, address):
    return _live_peer_allowed_ips_match(pubkey, [address + "/32"])


def _exact_peer_ipv4(cfg, target):
    """Return the sole safe /32; unsupported legacy peer shapes are inert."""
    allowed_lines = (target or {}).get("allowed_ips_lines")
    if allowed_lines is not None and len(allowed_lines) != 1:
        raise ClientError("peer должен иметь ровно одну строку AllowedIPs")
    raw_value = (allowed_lines[0] if allowed_lines is not None
                 else (target or {}).get("allowed_ips"))
    raw_items = [item.strip() for item in
                 str(raw_value or "").split(",")
                 if item.strip()]
    if len(raw_items) != 1:
        raise ClientError("peer должен иметь ровно один IPv4 /32 AllowedIPs")
    try:
        network = ipaddress.ip_network(raw_items[0], strict=False)
        subnet = ipaddress.ip_network(cfg.get("subnet") or "10.8.0.0/24",
                                       strict=False)
    except ValueError as error:
        raise ClientError("peer AllowedIPs имеет неверный формат") from error
    if (network.version != 4 or network.prefixlen != 32
            or not network.subnet_of(subnet)):
        raise ClientError("peer AllowedIPs должен быть IPv4 /32 внутри VPN-подсети")
    return str(network.network_address)


def _peer_mentions_ip(target, address):
    lines = (target or {}).get("allowed_ips_lines")
    if lines is None:
        lines = [(target or {}).get("allowed_ips") or ""]
    for line in lines:
        for item in str(line).split(","):
            try:
                if str(ipaddress.ip_network(
                        item.strip(), strict=False).network_address) == address:
                    return True
            except ValueError:
                continue
    return False


def _live_peer_absent(pubkey):
    output = _run(["wg", "show", "wg0", "allowed-ips"])
    return all(not line.split() or line.split()[0] != pubkey
               for line in output.splitlines())


def _fsync_parent(path):
    if os.name != "posix":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    fd = os.open(os.path.dirname(path), flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_client_operation(operation):
    parent = os.path.dirname(CLIENT_OP_MARK)
    os.makedirs(parent, mode=0o700, exist_ok=True)
    if os.name == "posix":
        info = os.lstat(parent)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0:
            raise ClientError("unsafe WireGuard operation parent")
        os.chmod(parent, 0o700)
    fd, tmp = tempfile.mkstemp(prefix=".wg-client-operation.", dir=parent)
    try:
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        else:
            os.chmod(tmp, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = None
            json.dump(operation, handle, ensure_ascii=True, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, CLIENT_OP_MARK)
        if os.name == "posix":
            info = os.lstat(CLIENT_OP_MARK)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or stat.S_IMODE(info.st_mode) != 0o600):
                raise ClientError("unsafe WireGuard operation marker")
        _fsync_parent(CLIENT_OP_MARK)
    finally:
        if fd is not None:
            os.close(fd)
        try:
            os.remove(tmp)
        except FileNotFoundError:
            pass


def _clear_client_operation():
    try:
        os.remove(CLIENT_OP_MARK)
    except FileNotFoundError:
        return
    _fsync_parent(CLIENT_OP_MARK)


def _dns_membership_guard(cfg, dns_pool=None, allow_existing_resume=False):
    """Do not change the peer cohort while DNS Rescue owns that cohort."""
    owned_pool = None
    try:
        if dns_pool is None:
            db_path = cfg.get("db")
            if not db_path:
                return
            import pool as pool_mod
            owned_pool = pool_mod.Pool(
                db_path, server=cfg.get("server") or "client-membership")
            dns_pool = owned_pool
        state = dns_pool.dns_state()
        unfinished = dns_pool.unfinished_dns_operations()
        exit_resume = dns_pool.get_setting("dns_exit_resume")
        boot_resume = dns_pool.get_setting("dns_boot_resume")
    except Exception as error:
        raise ClientError(
            "не удалось доказать отсутствие DNS Rescue ownership: %s"
            % type(error).__name__)
    finally:
        if owned_pool is not None:
            owned_pool.close()
    if (state.get("phase") in DNS_OWNED_PHASES
            or state.get("active_scope")
            or unfinished
            or ((exit_resume or boot_resume) and not allow_existing_resume)):
        raise ClientError(
            "состав WireGuard нельзя менять, пока DNS Rescue владеет клиентским охватом")


def _load_client_operation(cfg):
    try:
        if os.name == "posix":
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(CLIENT_OP_MARK, flags)
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                        or stat.S_IMODE(info.st_mode) != 0o600):
                    raise ClientError("unsafe WireGuard operation marker")
                with os.fdopen(fd, "r", encoding="utf-8") as handle:
                    fd = None
                    operation = json.load(handle)
            finally:
                if fd is not None:
                    os.close(fd)
        else:
            with open(CLIENT_OP_MARK, encoding="utf-8") as handle:
                operation = json.load(handle)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as error:
        raise ClientError("pending WireGuard client operation повреждена: %s" % error)
    required = ("kind", "name", "pubkey", "wg_config")
    if (not isinstance(operation, dict)
            or not all(operation.get(key) for key in required)
            or operation.get("kind") not in ("add", "delete")
            or not valid_name(operation.get("name"))):
        raise ClientError("pending WireGuard client operation имеет неверную форму")
    if operation["kind"] == "add":
        try:
            address = ipaddress.ip_address(operation.get("address") or "")
            subnet = ipaddress.ip_network(cfg.get("subnet") or "10.8.0.0/24",
                                           strict=False)
        except ValueError as error:
            raise ClientError("pending WireGuard client address неверен") from error
        if address.version != 4 or address not in subnet:
            raise ClientError("pending WireGuard client address вне подсети")
        if not operation.get("client_conf"):
            raise ClientError("pending WireGuard add не содержит client config")
    elif operation.get("address"):
        # Accept v1.13.1 delete markers while validating the legacy field.
        try:
            address = ipaddress.ip_address(operation["address"])
            subnet = ipaddress.ip_network(cfg.get("subnet") or "10.8.0.0/24",
                                           strict=False)
        except ValueError as error:
            raise ClientError("pending WireGuard client address неверен") from error
        if address.version != 4 or address not in subnet:
            raise ClientError("pending WireGuard client address вне подсети")
    if operation["kind"] == "delete":
        rollback_allowed = operation.get("rollback_allowed_ips")
        if rollback_allowed is None and operation.get("address"):
            rollback_allowed = [str(operation["address"]) + "/32"]
        if (not isinstance(rollback_allowed, list)
                or not all(isinstance(item, str) for item in rollback_allowed)):
            raise ClientError("pending WireGuard delete не содержит rollback AllowedIPs")
        _normalise_allowed_ips(rollback_allowed)
    resolution = operation.get("resolution") or "forward"
    if resolution not in ("forward", "rollback"):
        raise ClientError("pending WireGuard client resolution неверен")
    if resolution == "rollback" and not operation.get("rollback_wg_config"):
        raise ClientError("pending WireGuard rollback не содержит server config")
    return operation


def reconcile_client_operation(cfg, _locked=False, dns_pool=None):
    """Finish a crash-interrupted WG membership transaction idempotently."""
    if not _locked:
        try:
            with apply_mod.Flock(cfg.get("lock") or "/run/vpn-agent.lock"):
                return reconcile_client_operation(
                    cfg, _locked=True, dns_pool=dns_pool)
        except apply_mod.ApplyError as error:
            raise ClientError(str(error))
    operation = _load_client_operation(cfg)
    if operation is None:
        return {"ok": True, "action": "nothing-to-reconcile"}
    # This marker was durably created before the DNS compensation descriptor.
    # Once DNS is physically detached, finishing its exact idempotent target is
    # safe; the resume path must re-prove the old WG identity and cancels on a
    # changed cohort. New CRUD remains blocked by the descriptor.
    _dns_membership_guard(
        cfg, dns_pool=dns_pool, allow_existing_resume=True)
    name = operation["name"]
    pubkey = operation["pubkey"]
    address = operation.get("address")
    client_path = os.path.join(CLIENTS_DIR, name + ".conf")
    resolution = operation.get("resolution") or "forward"
    try:
        if resolution == "rollback":
            _atomic_write(WG_CONF, operation["rollback_wg_config"], 0o600)
            if operation["kind"] == "add":
                _run(["wg", "set", "wg0", "peer", pubkey, "remove"])
                if not _live_peer_absent(pubkey):
                    raise ClientError("pending live peer rollback не подтверждён")
                if os.path.exists(client_path):
                    os.remove(client_path)
                if (_wg0_text() != operation["rollback_wg_config"]
                        or os.path.exists(client_path)):
                    raise ClientError("pending durable add rollback не подтверждён")
            else:
                rollback_allowed = operation.get("rollback_allowed_ips") or [address + "/32"]
                _set_live_peer_allowed_ips(
                    pubkey, operation.get("rollback_psk"), rollback_allowed)
                if not _live_peer_allowed_ips_match(pubkey, rollback_allowed):
                    raise ClientError("pending live peer restore не подтверждён")
                saved = operation.get("rollback_client_conf")
                if saved is not None:
                    os.makedirs(CLIENTS_DIR, mode=0o700, exist_ok=True)
                    os.chmod(CLIENTS_DIR, 0o700)
                    _atomic_write(client_path, saved, 0o600)
                elif os.path.exists(client_path):
                    os.remove(client_path)
                if (_wg0_text() != operation["rollback_wg_config"]
                        or (saved is not None) != os.path.isfile(client_path)):
                    raise ClientError("pending durable delete rollback не подтверждён")
        elif operation["kind"] == "add":
            _atomic_write(WG_CONF, operation["wg_config"], 0o600)
            _set_live_peer(pubkey, operation.get("psk"), address)
            if not _live_peer_matches(pubkey, address):
                raise ClientError("pending live peer add не подтверждён")
            os.makedirs(CLIENTS_DIR, exist_ok=True)
            os.chmod(CLIENTS_DIR, 0o700)
            _atomic_write(client_path, operation["client_conf"], 0o600)
            if _wg0_text() != operation["wg_config"] or not os.path.isfile(client_path):
                raise ClientError("pending durable peer add не подтверждён")
        else:
            _atomic_write(WG_CONF, operation["wg_config"], 0o600)
            _run(["wg", "set", "wg0", "peer", pubkey, "remove"])
            if not _live_peer_absent(pubkey):
                raise ClientError("pending live peer delete не подтверждён")
            if os.path.exists(client_path):
                os.remove(client_path)
            if _wg0_text() != operation["wg_config"] or os.path.exists(client_path):
                raise ClientError("pending durable peer delete не подтверждён")
    except (ClientError, OSError) as error:
        raise ClientError("pending WireGuard client operation не завершена: %s" % error)
    try:
        _clear_client_operation()
        pending = False
    except OSError:
        # The target is already proven.  Keeping an idempotent marker cannot
        # change the externally reported outcome on the next reconciliation.
        pending = True
    return {"ok": True, "action": "client-operation-reconciled",
            "recovery_pending": pending}


def next_free_ip(cfg, params=None):
    p = params or server_params(cfg)
    used = _used_ips(cfg, _parse_peers(p["text"]), p["net"])
    for host in p["net"].hosts():
        s = str(host)
        if s == p["wg_ip"]:
            continue
        if s not in used:
            return s
    raise ClientError("свободных адресов в подсети нет")


def client_inventory(cfg):
    """Return readable peers even when strict allocation is currently unavailable."""
    rows = list_clients(cfg)
    try:
        next_ip = next_free_ip(cfg)
    except ClientError as error:
        return {"clients": rows, "next_ip": None, "can_add": False,
                "add_error": str(error)}
    return {"clients": rows, "next_ip": next_ip, "can_add": True, "add_error": ""}


# ─────────────────────────── создать / удалить ──────────────────────────
def add_client(cfg, name, _locked=False, dns_pool=None):
    if not _locked:
        try:
            with apply_mod.Flock(cfg.get("lock") or "/run/vpn-agent.lock"):
                return add_client(cfg, name, _locked=True, dns_pool=dns_pool)
        except apply_mod.ApplyError as error:
            raise ClientError(str(error))
    reconcile_client_operation(cfg, _locked=True, dns_pool=dns_pool)
    _dns_membership_guard(cfg, dns_pool=dns_pool)
    if not valid_name(name):
        raise ClientError("имя: латиница/цифры/._- до 32 символов")
    p = server_params(cfg)
    peers = _parse_peers(p["text"])
    if any((c["name"] or "") == name for c in peers) or os.path.isfile(os.path.join(CLIENTS_DIR, name + ".conf")):
        raise ClientError("клиент '%s' уже есть" % name)
    # Validate the complete current inventory before generating any secret or
    # writing a journal. Unsupported/overlapping legacy shapes must never let
    # a newly allocated /32 steal another peer's route.
    ip = next_free_ip(cfg, params=p)
    priv = _run(["wg", "genkey"]).strip()
    pub = _run(["wg", "pubkey"], inp=priv + "\n").strip()
    psk = _run(["wg", "genpsk"]).strip()

    # Durable and live membership are one guarded transaction. Every failure
    # restores the old file and removes a possibly half-added live peer.
    block = "\n[Peer]\n# %s\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s/32\n" % (name, pub, psk, ip)
    original = p["text"]
    text = original.rstrip("\n") + "\n" + block
    conf = client_conf_build(p, name, priv, psk, ip)
    client_path = os.path.join(CLIENTS_DIR, name + ".conf")
    operation = {
        "kind": "add", "name": name, "pubkey": pub, "psk": psk,
        "address": ip, "wg_config": text, "client_conf": conf,
        "rollback_wg_config": original}
    _write_client_operation(operation)
    try:
        _atomic_write(WG_CONF, text, 0o600)
        _set_live_peer(pub, psk, ip)
        if not _live_peer_matches(pub, ip):
            raise ClientError("live WireGuard peer не подтверждён")
        os.makedirs(CLIENTS_DIR, exist_ok=True)
        os.chmod(CLIENTS_DIR, 0o700)
        _atomic_write(client_path, conf, 0o600)
        if _wg0_text() != text or not os.path.isfile(client_path):
            raise ClientError("durable WireGuard client не подтверждён")
        if not _live_peer_matches(pub, ip):
            raise ClientError("live WireGuard peer изменился до commit")
    except (ClientError, OSError) as error:
        rollback_errors = []
        try:
            rollback_operation = dict(operation, resolution="rollback")
            _write_client_operation(rollback_operation)
        except OSError:
            rollback_errors.append("rollback-intent")
        if not rollback_errors:
            try:
                reconcile_client_operation(cfg, _locked=True, dns_pool=dns_pool)
            except ClientError:
                rollback_errors.append("rollback")
        suffix = ("; rollback incomplete: " + ",".join(rollback_errors)
                  if rollback_errors else "")
        raise ClientError(str(error) + suffix)
    try:
        _clear_client_operation()
        pending = False
    except OSError:
        pending = True
    return {"name": name, "ip": ip, "pubkey": pub,
            "recovery_pending": pending}


def _stored_conf_for_peer(target):
    """Resolve at most one stored client profile by its exact peer IPv4."""
    matches = []
    if os.path.isdir(CLIENTS_DIR):
        for filename in os.listdir(CLIENTS_DIR):
            if not filename.endswith(".conf"):
                continue
            candidate = filename[:-5]
            if not valid_name(candidate):
                continue
            address = _stored_ip(candidate)
            if address and _peer_mentions_ip(target, address):
                matches.append(candidate)
    if len(matches) > 1:
        raise ClientError("несколько сохранённых профилей соответствуют одному peer")
    return matches[0] if matches else None


def delete_client(cfg, name, pubkey=None, _locked=False, dns_pool=None):
    if not _locked:
        try:
            with apply_mod.Flock(cfg.get("lock") or "/run/vpn-agent.lock"):
                return delete_client(
                    cfg, name, pubkey=pubkey, _locked=True, dns_pool=dns_pool)
        except apply_mod.ApplyError as error:
            raise ClientError(str(error))
    reconcile_client_operation(cfg, _locked=True, dns_pool=dns_pool)
    _dns_membership_guard(cfg, dns_pool=dns_pool)
    if pubkey is None and not valid_name(name):
        raise ClientError("плохое имя")
    p = server_params(cfg)
    peers = _parse_peers(p["text"])
    if pubkey is not None:
        if not isinstance(pubkey, str) or not pubkey or len(pubkey) > 128:
            raise ClientError("неверный PublicKey клиента")
        matched = [peer for peer in peers if peer.get("pubkey") == pubkey]
        if len(matched) != 1:
            raise ClientError("peer с указанным PublicKey не найден или неоднозначен")
        target = matched[0]
    else:
        matched = [peer for peer in peers if (peer.get("name") or "") == name]
        if len(matched) > 1:
            raise ClientError("имя клиента неоднозначно; нужен точный PublicKey")
        target = matched[0] if matched else None
        if target is None:                       # попробуем по адресу сохранённого .conf
            ip = _stored_ip(name)
            matched = [peer for peer in peers if ip and _peer_mentions_ip(peer, ip)]
            if len(matched) > 1:
                raise ClientError("профиль клиента соответствует нескольким peers")
            target = matched[0] if matched else None
    pub = target.get("pubkey") if target else None
    conf_name = _stored_conf_for_peer(target) if pub else (name if valid_name(name) else None)
    operation_name = conf_name or ("peer-" + hashlib.sha256(
        pub.encode("utf-8")).hexdigest()[:16] if pub else name)
    cf = os.path.join(CLIENTS_DIR, (conf_name or operation_name) + ".conf")
    had_conf = os.path.isfile(cf)
    if not pub and not had_conf:
        raise ClientError("клиент '%s' не найден" % name)
    rollback_allowed = _peer_allowed_ips(target) if pub else None
    original = p["text"]
    replacement = _remove_peer_block_text(original, pub) if pub else original
    saved_conf = None
    if had_conf:
        try:
            with open(cf, encoding="utf-8") as handle:
                saved_conf = handle.read()
        except OSError as error:
            raise ClientError(str(error))
    if pub:
        operation = {
            "kind": "delete", "name": operation_name, "pubkey": pub,
            "rollback_allowed_ips": rollback_allowed,
            "wg_config": replacement, "rollback_wg_config": original,
            "rollback_psk": target.get("psk"),
            "rollback_client_conf": saved_conf}
        _write_client_operation(operation)
    try:
        if pub:
            _atomic_write(WG_CONF, replacement, 0o600)
            _run(["wg", "set", "wg0", "peer", pub, "remove"])
            if not _live_peer_absent(pub):
                raise ClientError("live WireGuard peer removal не подтверждён")
        if had_conf:
            os.remove(cf)
        if (pub and (pub in _wg0_text() or not _live_peer_absent(pub))) \
                or os.path.isfile(cf):
            raise ClientError("удаление WireGuard client не подтверждено")
    except (ClientError, OSError) as error:
        rollback_errors = []
        if pub:
            try:
                rollback_operation = dict(operation, resolution="rollback")
                _write_client_operation(rollback_operation)
            except OSError:
                rollback_errors.append("rollback-intent")
            if not rollback_errors:
                try:
                    reconcile_client_operation(cfg, _locked=True, dns_pool=dns_pool)
                except ClientError:
                    rollback_errors.append("rollback")
        else:
            try:
                if had_conf and saved_conf is not None:
                    _atomic_write(cf, saved_conf, 0o600)
            except OSError:
                rollback_errors.append("client-conf")
        suffix = ("; rollback incomplete: " + ",".join(rollback_errors)
                  if rollback_errors else "")
        raise ClientError(str(error) + suffix)
    pending = False
    if pub:
        try:
            _clear_client_operation()
        except OSError:
            pending = True
    return {"name": name or operation_name, "pubkey": pub,
            "removed_peer": bool(pub), "removed_conf": had_conf,
            "recovery_pending": pending}


def _remove_peer_block_text(text, pubkey):
    """Убрать [Peer]-блок с данным PublicKey из wg0.conf, сохранив остальное."""
    lines = text.splitlines()
    out = []
    i = 0
    while i < len(lines):
        if re.match(r"(?i)^\s*\[Peer\]\s*$", lines[i]):
            j = i + 1
            block = [lines[i]]
            while j < len(lines) and not re.match(r"(?i)^\s*\[Peer\]\s*$", lines[j]) \
                    and not re.match(r"(?i)^\s*\[Interface\]\s*$", lines[j]):
                block.append(lines[j])
                j += 1
            if any((lambda match: match is not None and match.group(1) == pubkey)(
                    re.match(r"(?i)^\s*PublicKey\s*=\s*(\S+)\s*$", b))
                    for b in block):
                # пропустить блок (и ведущие комментарии-имя прямо перед ним)
                while out and re.match(r"(?m)^\s*#", out[-1]):
                    out.pop()
                i = j
                continue
            out.extend(block)
            i = j
            continue
        out.append(lines[i])
        i += 1
    return "\n".join(out).rstrip("\n") + "\n"


def _remove_peer_block(text, pubkey):
    _atomic_write(WG_CONF, _remove_peer_block_text(text, pubkey), 0o600)


# ─────────────────────────── сборка .conf / чтение ──────────────────────
def client_conf_build(p, name, priv, psk, ip):
    return ("[Interface]\nPrivateKey = %s\nAddress = %s/32\nDNS = %s\n\n"
            "[Peer]\nPublicKey = %s\nPresharedKey = %s\nEndpoint = %s:%d\n"
            "AllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n"
            % (priv, ip, p["dns"], p["server_pub"], psk, p["host"], p["port"]))


def client_conf_text(name):
    if not valid_name(name):
        raise ClientError("плохое имя")
    path = os.path.join(CLIENTS_DIR, name + ".conf")
    if not os.path.isfile(path):
        raise ClientError("нет сохранённого .conf для '%s' (создан вне панели?)" % name)
    with open(path, encoding="utf-8") as f:
        return f.read()


def _atomic_write(path, text, mode):
    parent = os.path.dirname(path) or "."
    prefix = ".%s.redut-tmp-" % os.path.basename(path)
    if os.name == "posix":
        for name in os.listdir(parent):
            if not name.startswith(prefix):
                continue
            stale = os.path.join(parent, name)
            info = os.lstat(stale)
            if stat.S_ISREG(info.st_mode) and info.st_uid == 0:
                os.remove(stale)
            else:
                raise OSError("unsafe stale atomic temp")
    fd, tmp = tempfile.mkstemp(prefix=prefix, dir=parent)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise OSError("atomic temp is not a regular file")
        if os.name == "posix":
            os.fchmod(fd, mode)
        else:
            os.chmod(tmp, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = None
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        if os.name == "posix":
            final = os.lstat(path)
            if (not stat.S_ISREG(final.st_mode) or final.st_uid != 0
                    or stat.S_IMODE(final.st_mode) != mode):
                raise OSError("atomic target permissions are not proven")
        _fsync_parent(path)
    finally:
        if fd is not None:
            os.close(fd)
        try:
            os.remove(tmp)
        except FileNotFoundError:
            pass
