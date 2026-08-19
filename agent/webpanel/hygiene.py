# -*- coding: utf-8 -*-
"""Гигиена узла для карточки статуса: белый список РФ и очистка следов.

Всё из файлов (конфиг dnsmasq, дамп ipset сетей, стат-файл очистки) — без subprocess,
как sysinfo: данные едут в каждый 30-секундный опрос /api/status. Нет файла или не Linux
-> у блока `{"on": False}` либо None-поля, и карточка просто не покажет строку.

Даты отдаём как epoch (mtime файла / отметка скрипта): дату в СВОЁМ часовом поясе
форматирует уже браузер владельца (`new Date(epoch*1000)`), а возраст «сегодня/N дн
назад» фронт считает сам.
"""
import json
import os

WHITELIST_CONF = "/etc/dnsmasq.d/ru-whitelist.conf"   # домены -> ipset ru_whitelist (dnsmasq)
NET_IPSET_FILE = "/etc/ru_whitelist_net.ipset"        # сети РФ (IP/CIDR), дамп ipset ru_whitelist_net
CLEANUP_STAT = "/var/lib/vpn-panel/cleanup-stat.json"  # пишет server_cleanup.sh после каждой чистки


def _count_prefix(path, prefix):
    """Сколько строк файла начинаются с prefix (домены `ipset=/`, сети `add `). Нет файла -> 0."""
    n = 0
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith(prefix):
                    n += 1
    except OSError:
        return 0
    return n


def _mtime(*paths):
    """Самый свежий mtime из путей (epoch) — «когда белый список обновляли». Нет файлов -> None."""
    best = None
    for p in paths:
        try:
            m = os.path.getmtime(p)
        except OSError:
            continue
        best = m if best is None else max(best, m)
    return best


def whitelist_stat(has_dnsmasq, conf=WHITELIST_CONF, net_file=NET_IPSET_FILE):
    """Статус белого списка РФ. has_dnsmasq — из config.json (узел ставился с dnsmasq).

    on=False -> {"on": False} (узел без белого списка: весь трафик уходит в исходящий канал).
    on=True  -> домены (dnsmasq-конфиг), сети РФ (дамп ipset), время обновления (mtime файлов).
    """
    if not has_dnsmasq:
        return {"on": False}
    return {"on": True,
            "domains": _count_prefix(conf, "ipset=/"),
            "nets": _count_prefix(net_file, "add "),
            "updated_at": _mtime(net_file, conf)}


def cleanup_stat(path=CLEANUP_STAT):
    """Статистика очистки следов из стат-файла server_cleanup.sh.

    Формат: {"last_at": epoch, "freed_24h": bytes, "runs_24h": n}. Нет файла -> {"on": False}
    (чистка выключена: CLEANUP=0, напр. тест-стенд).
    """
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
    except (OSError, ValueError):
        return {"on": False}
    if not isinstance(d, dict):
        return {"on": False}
    return {"on": True, "last_at": d.get("last_at"),
            "freed_24h": d.get("freed_24h"), "runs_24h": d.get("runs_24h")}


def snapshot(cfg, conf=WHITELIST_CONF, net_file=NET_IPSET_FILE, stat=CLEANUP_STAT):
    """Обе гигиены одним словарём для /api/status. cfg — конфиг панели (has_dnsmasq)."""
    return {"whitelist": whitelist_stat(bool((cfg or {}).get("has_dnsmasq")), conf, net_file),
            "cleanup": cleanup_stat(stat)}
