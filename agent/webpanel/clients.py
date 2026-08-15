# -*- coding: utf-8 -*-
"""Управление клиентскими WireGuard-конфигами прямо из панели (панель работает от root).

Список / создать / удалить / скачать / QR. Пиры живут в /etc/wireguard/wg0.conf (правим
файл, сохраняя структуру и комментарии-имена — БЕЗ `wg-quick save`, он бы затёр PostUp и
имена), применяем на живом интерфейсе через `wg set` (без разрыва других клиентов).
Полный клиентский `.conf` (с приватником — его нет в wg0.conf) храним в
/etc/wireguard/clients/<name>.conf (0600) — источник для скачивания/QR.
"""
import ipaddress
import os
import re
import subprocess
import tempfile

WG_CONF = "/etc/wireguard/wg0.conf"
CLIENTS_DIR = "/etc/wireguard/clients"
SRV_PUB = "/etc/wireguard/server_public.key"
NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")


class ClientError(Exception):
    pass


def _run(args, inp=None, timeout=20):
    p = subprocess.run(args, capture_output=True, text=True, input=inp, timeout=timeout)
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
        aip = re.search(r"(?im)^\s*AllowedIPs\s*=\s*(\S+)", body)
        psk = re.search(r"(?im)^\s*PresharedKey\s*=\s*(\S+)", body)
        nm = re.search(r"(?m)^\s*#\s*(.+?)\s*$", body)
        peers.append({"name": nm.group(1).strip() if nm else None,
                      "pubkey": pub.group(1) if pub else None,
                      "psk": psk.group(1) if psk else None,
                      "allowed_ips": aip.group(1) if aip else None})
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
    stored = set()
    if os.path.isdir(CLIENTS_DIR):
        stored = {fn[:-5] for fn in os.listdir(CLIENTS_DIR) if fn.endswith(".conf")}
    out = []
    for peer in _parse_peers(p["text"]):
        ip = (peer["allowed_ips"] or "").split("/")[0]
        d = dump.get(peer["pubkey"] or "", {})
        name = peer["name"]
        # если имени в конфиге нет, но есть сохранённый .conf с этим ip — подставим
        if not name:
            for s in stored:
                if _stored_ip(s) == ip:
                    name = s
                    break
        out.append({"name": name or ("peer-" + ip.replace(".", "-") if ip else "peer"),
                    "ip": ip, "pubkey": peer["pubkey"],
                    "handshake": d.get("handshake", 0), "rx": d.get("rx", 0),
                    "tx": d.get("tx", 0), "has_conf": (name in stored) if name else False})
    return out


def _stored_ip(name):
    try:
        with open(os.path.join(CLIENTS_DIR, name + ".conf"), encoding="utf-8") as f:
            m = re.search(r"(?im)^\s*Address\s*=\s*(\d+\.\d+\.\d+\.\d+)", f.read())
            return m.group(1) if m else ""
    except OSError:
        return ""


def _used_ips(peers, net):
    used = {str(net.network_address + 1)}       # .1 сервер
    for peer in peers:
        if peer["allowed_ips"]:
            used.add(peer["allowed_ips"].split("/")[0])
    return used


def next_free_ip(cfg):
    p = server_params(cfg)
    used = _used_ips(_parse_peers(p["text"]), p["net"])
    for host in p["net"].hosts():
        s = str(host)
        if s == p["wg_ip"]:
            continue
        if s not in used:
            return s
    raise ClientError("свободных адресов в подсети нет")


# ─────────────────────────── создать / удалить ──────────────────────────
def add_client(cfg, name):
    if not valid_name(name):
        raise ClientError("имя: латиница/цифры/._- до 32 символов")
    p = server_params(cfg)
    peers = _parse_peers(p["text"])
    if any((c["name"] or "") == name for c in peers) or os.path.isfile(os.path.join(CLIENTS_DIR, name + ".conf")):
        raise ClientError("клиент '%s' уже есть" % name)
    ip = next_free_ip(cfg)
    priv = _run(["wg", "genkey"]).strip()
    pub = _run(["wg", "pubkey"], inp=priv + "\n").strip()
    psk = _run(["wg", "genpsk"]).strip()

    # 1) дописать пир в wg0.conf (сохраняя структуру/PostUp/имена)
    block = "\n[Peer]\n# %s\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s/32\n" % (name, pub, psk, ip)
    text = p["text"].rstrip("\n") + "\n" + block
    _atomic_write(WG_CONF, text, 0o600)

    # 2) применить на живом интерфейсе (psk — через файл, wg не берёт inline)
    with tempfile.NamedTemporaryFile("w", delete=False, dir="/dev/shm" if os.path.isdir("/dev/shm") else None) as tf:
        tf.write(psk + "\n")
        pskfile = tf.name
    try:
        _run(["wg", "set", "wg0", "peer", pub, "preshared-key", pskfile, "allowed-ips", ip + "/32"])
    finally:
        try:
            os.remove(pskfile)
        except OSError:
            pass

    # 3) сохранить клиентский .conf (с приватником) для скачивания/QR
    conf = client_conf_build(p, name, priv, psk, ip)
    os.makedirs(CLIENTS_DIR, exist_ok=True)
    os.chmod(CLIENTS_DIR, 0o700)
    _atomic_write(os.path.join(CLIENTS_DIR, name + ".conf"), conf, 0o600)
    return {"name": name, "ip": ip, "pubkey": pub}


def delete_client(cfg, name):
    if not valid_name(name):
        raise ClientError("плохое имя")
    p = server_params(cfg)
    peers = _parse_peers(p["text"])
    target = next((c for c in peers if (c["name"] or "") == name), None)
    pub = target["pubkey"] if target else None
    if not pub:                                   # имени нет в конфиге — попробуем по .conf
        ip = _stored_ip(name)
        target = next((c for c in peers if (c["allowed_ips"] or "").split("/")[0] == ip and ip), None)
        pub = target["pubkey"] if target else None
    if pub:
        _remove_peer_block(p["text"], pub)
        try:
            _run(["wg", "set", "wg0", "peer", pub, "remove"])
        except ClientError:
            pass
    cf = os.path.join(CLIENTS_DIR, name + ".conf")
    if os.path.isfile(cf):
        os.remove(cf)
    if not pub and not os.path.isfile(cf):
        raise ClientError("клиент '%s' не найден" % name)
    return {"name": name, "removed_peer": bool(pub)}


def _remove_peer_block(text, pubkey):
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
            if any(re.match(r"(?i)^\s*PublicKey\s*=\s*" + re.escape(pubkey), b) for b in block):
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
    _atomic_write(WG_CONF, "\n".join(out).rstrip("\n") + "\n", 0o600)


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
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    try:
        os.chmod(tmp, mode)
    except OSError:
        pass
    os.replace(tmp, path)
