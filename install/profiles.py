#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""profiles.py — профили серверов для bootstrap.py (дефолты = схема node1).

Профиль описывает ВСЁ, что не определяется автоматически на сервере: подсеть wg,
порт, версию sing-box, upstream-прокси, клиентов, порт панели, microsocks, dnsmasq.
`host`/`root_pw` приходят из аргументов bootstrap.py, а `gw`/`wan`/`server_ip`
определяются на сервере (`ip route show default`, IP на WAN) — их тут НЕТ.

Новый сервер по схеме node1 = тот же профиль, меняются только host+pw:
    python bootstrap.py --host <IP> --pw <root_pw> --name node1

profiles.json — читаемое зеркало этих данных (перегенерить: `python profiles.py --dump`).
Секреты провайдеров/SMTP тут НЕ хранятся — они в panel/.secrets.local.json (как в deploy.py).
"""
import json
import ipaddress
import os
import re
import sys

PROFILES = {
    # Эталон — рабочая схема node1 (слепок 2026-08-14, см. SYSTEM-INVENTORY.md).
    "node1": {
        "subnet": "10.8.0.0/24",          # клиентская сеть wg0
        "wg_ip": "10.8.0.1",              # адрес сервера в wg0
        "wg_port": 51820,
        "singbox_version": "1.11.7",      # статический бинарь с GitHub SagerNet/sing-box
        "upstream": {                      # апстрим-прокси (зарубежный трафик уходит сюда)
            # Исходящий канал. Пусто -> узел выпускает трафик сам, своим адресом.
            "host": "", "socks": 0, "http": 0, "user": "", "pass": "",
        },
        "clients": [                       # ≥1 клиент; ключи+psk генерятся на сервере
            {"name": "phone1", "addr": "10.8.0.5"},
        ],
        "panel_port": 8443,
        "dnsmasq": True,                  # белый список РФ ВКЛ по умолчанию: ру-сайты (банки, госуслуги, Почта РФ)
        # идут напрямую адресом узла, остальной трафик — через исходящий канал
        # SOCKS5 для приложений (:1080). Пароль пусто -> установщик сгенерирует случайный
        # и сохранит в /etc/microsocks.env (install.sh §8); заглушка в юнит не попадает.
        "microsocks": {"port": 1080, "user": "proxyuser", "pass": ""},
    },
}


def _merge_json_overrides():
    """Если рядом лежит profiles.json — наложить его поверх встроенных дефолтов."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "profiles.json")
    if not os.path.isfile(path):
        return
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (ValueError, OSError):
        return
    for name, prof in (data or {}).items():
        if isinstance(prof, dict):
            PROFILES.setdefault(name, {}).update(prof)


_merge_json_overrides()


def build_profile(name, host, root_pw, overrides=None):
    """Собрать резолвнутый профиль: базовый профиль + host/pw + CLI-оверрайды.

    gw/wan/server_ip НЕ выставляются тут — их определяет bootstrap.py на сервере.
    role выводится как vpn-<name>. Возвращает новый dict (базовый не мутируется).
    """
    if name not in PROFILES:
        raise KeyError("нет профиля '%s' (есть: %s)" % (name, ", ".join(PROFILES)))
    import copy
    p = copy.deepcopy(PROFILES[name])
    p["name"] = name
    p["role"] = "vpn-%s" % name
    p["host"] = host
    p["root_pw"] = root_pw
    for k, v in (overrides or {}).items():
        if v is not None:
            p[k] = v
    if p["subnet"] != PROFILES[name]["subnet"]:
        # --subnet replaces the address space, including inherited addresses.
        # Preserve host offsets (.1 for wg0, .5 for the default phone), while
        # rejecting an override too small to contain those hosts before SSH.
        old_net = ipaddress.IPv4Network(PROFILES[name]["subnet"], strict=False)
        new_net = ipaddress.IPv4Network(p["subnet"], strict=False)

        def rebase(address):
            old = ipaddress.IPv4Address(address)
            offset = int(old) - int(old_net.network_address)
            if old not in old_net or not 0 < offset < new_net.num_addresses - 1:
                raise ValueError("адрес %s не помещается в подсеть %s" % (address, new_net))
            return str(new_net.network_address + offset)

        if not (overrides or {}).get("wg_ip"):
            p["wg_ip"] = rebase(PROFILES[name].get("wg_ip")
                                or str(old_net.network_address + 1))
        if (overrides or {}).get("clients") is None:
            for client in p["clients"]:
                client["addr"] = rebase(client["addr"])
    # производные
    p.setdefault("wg_ip", p["subnet"].split("/")[0].rsplit(".", 1)[0] + ".1")
    p["wg_addr"] = "%s/%s" % (p["wg_ip"], p["subnet"].split("/")[1])
    return p


def effective_wg_ip(profile, subnet):
    """Адрес сервера в wg0 для ДЕЙСТВУЮЩЕЙ подсети.

    Явный wg_ip профиля осмыслен только в его родной подсети. Если узел живёт
    в другой (SUBNET= при установке или UPDATE=1 читает подсеть с живого узла),
    берём .1 действующей — на этом допущении стоит вся система (DNS клиентов,
    dnsmasq listen-address, конфиг панели). Иначе обновление узла node2
    (подсеть 10.10.10.0/24) профилем node1 (wg_ip 10.8.0.1) прописало бы wg0
    адрес чужой подсети и после ребута у клиентов умер бы DNS (ревью Ф2).
    """
    network = ipaddress.IPv4Network(str(subnet), strict=False)
    if network.num_addresses < 4:
        raise ValueError("подсеть %s не содержит отдельного адреса wg0" % network)
    first = str(network.network_address + 1)
    if subnet and (profile or {}).get("subnet") != subnet:
        return first
    return (profile or {}).get("wg_ip") or first


def parse_clients(spec, subnet, allow_empty=False):
    """Parse a client count/list and validate every address against *subnet*.

    Plain names receive consecutive addresses from network offset 2.  An item
    may also preserve an existing address as ``name:IPv4`` during an update.
    """
    network = ipaddress.IPv4Network(str(subnet), strict=False)
    value = str(spec or "").strip()
    if re.fullmatch(r"\d+", value):
        count = int(value)
        if count > max(0, network.num_addresses - 3):
            raise ValueError("клиент %s не помещается в подсеть %s" %
                             (count, network))
        entries = ["client%d" % i for i in range(1, count + 1)]
    else:
        entries = [item.strip() for item in value.split(",") if item.strip()]
    if not entries:
        if allow_empty:
            return []
        raise ValueError("список клиентов должен содержать хотя бы одного клиента")

    reserved = {network.network_address, network.broadcast_address}
    if network.num_addresses >= 2:
        reserved.add(network.network_address + 1)  # wg0 server address
    used = set()
    used_names = set()
    clients = []
    for offset, entry in enumerate(entries, start=2):
        if ":" in entry:
            name, raw_address = (part.strip() for part in entry.split(":", 1))
            try:
                address = ipaddress.IPv4Address(raw_address)
            except ipaddress.AddressValueError:
                raise ValueError("неверный IPv4-адрес клиента %s" % entry)
        else:
            name = entry
            address = network.network_address + offset
        if not name:
            raise ValueError("имя клиента не может быть пустым")
        if name in used_names:
            raise ValueError("имя клиента %s повторяется" % name)
        if address not in network or address in reserved:
            raise ValueError("адрес клиента %s не помещается в подсеть %s" %
                             (address, network))
        if address in used:
            raise ValueError("адрес клиента %s повторяется" % address)
        used_names.add(name)
        used.add(address)
        clients.append({"name": name, "addr": str(address)})
    return clients


def _shq(v):
    """Безопасно закавычить значение для params.sh (одинарные кавычки)."""
    s = str(v)
    return "'" + s.replace("'", "'\\''") + "'"


def render_params(p, net):
    """Собрать текст params.sh, который install.sh сорсит. net={wan,gw,server_ip}."""
    up = p["upstream"]
    ms = p["microsocks"]
    dns_server = p["wg_ip"] if p.get("dnsmasq") else "1.1.1.1"
    clients = " ".join("%s:%s" % (c["name"], c["addr"]) for c in p["clients"])
    kv = [
        ("NAME", p["name"]),
        ("ROLE", p["role"]),
        ("SUBNET", p["subnet"]),
        ("WG_IP", p["wg_ip"]),
        ("WG_ADDR", p["wg_addr"]),
        ("WG_PORT", p["wg_port"]),
        ("WAN", net["wan"]),
        ("GW", net["gw"]),
        ("SERVER_IP", net["server_ip"]),
        ("SINGBOX_VERSION", p["singbox_version"]),
        ("UP_HOST", up["host"]),
        ("UP_SOCKS", up["socks"]),
        ("UP_HTTP", up["http"]),
        ("UP_USER", up["user"]),
        ("UP_PASS", up["pass"]),
        # 1 — канал задан человеком явно (--upstream): перебиваем живой конфиг.
        # 0 — это дефолт профиля: при переустановке живой канал важнее (см. install.sh §5).
        ("UP_FORCE", "1" if p.get("upstream_forced") else "0"),
        ("MICROSOCKS_PORT", ms["port"]),
        ("MICROSOCKS_USER", ms["user"]),
        ("MICROSOCKS_PASS", ms["pass"]),
        ("DNSMASQ", "1" if p.get("dnsmasq") else "0"),
        ("DNS_SERVER", dns_server),
        ("CLIENTS", clients),
    ]
    lines = ["# params.sh — сгенерирован bootstrap.py, сорсится install.sh. НЕ в репозиторий."]
    lines += ["%s=%s" % (k, _shq(v)) for k, v in kv]
    return "\n".join(lines) + "\n"


def _dump_json():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "profiles.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(PROFILES, f, ensure_ascii=False, indent=2)
    print("записан %s" % path)


if __name__ == "__main__":
    if "--dump" in sys.argv[1:]:
        _dump_json()
    else:
        print(json.dumps(PROFILES, ensure_ascii=False, indent=2))
