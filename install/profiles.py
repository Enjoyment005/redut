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
import os
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
        "dnsmasq": False,                  # осознанно выкл (весь трафик через прокси, §7 node1/README)
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
    # производные
    p.setdefault("wg_ip", p["subnet"].split("/")[0].rsplit(".", 1)[0] + ".1")
    p["wg_addr"] = "%s/%s" % (p["wg_ip"], p["subnet"].split("/")[1])
    return p


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
