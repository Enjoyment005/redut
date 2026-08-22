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
import time

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


def _cleanup_run(run):
    """Один запуск из нового dict-формата или старого [timestamp, bytes]."""
    precise = isinstance(run, dict) and "journal" in run
    if isinstance(run, list) and len(run) == 2:
        run = {"at": run[0], "freed": run[1]}
    if not isinstance(run, dict):
        return None
    at, freed = run.get("at"), run.get("freed")
    if not isinstance(at, (int, float)) or not isinstance(freed, (int, float)):
        return None
    if at < 0 or freed < 0:
        return None
    return at, int(freed), precise


def cleanup_stat(path=CLEANUP_STAT, now=None):
    """Статистика очистки следов из стат-файла server_cleanup.sh.

    Если есть runs, скользящие последние 24 часа всегда пересчитываем на момент
    запроса панели. Сохранённые freed_24h/runs_24h — лишь совместимый кэш, который
    между cron-запусками устаревает. Старый файл без runs по-прежнему читается.

    Нет файла -> {"on": False} (чистка выключена: CLEANUP=0, напр. тест-стенд).
    """
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
    except (OSError, ValueError):
        return {"on": False}
    if not isinstance(d, dict):
        return {"on": False}
    runs = d.get("runs")
    if isinstance(runs, list):
        now = time.time() if now is None else now
        recent = []
        for raw in runs:
            run = _cleanup_run(raw)
            # До пяти минут вперёд терпим на случай коррекции часов сервера.
            if run and now - 86400 < run[0] <= now + 300:
                recent.append(run)
        return {"on": True, "last_at": d.get("last_at"),
                "freed_24h": sum(r[1] for r in recent), "runs_24h": len(recent),
                "measured_runs_24h": sum(1 for r in recent if r[2]),
                "complete_24h": all(r[2] for r in recent)}
    return {"on": True, "last_at": d.get("last_at"),
            "freed_24h": d.get("freed_24h"), "runs_24h": d.get("runs_24h")}


def snapshot(cfg, conf=WHITELIST_CONF, net_file=NET_IPSET_FILE, stat=CLEANUP_STAT):
    """Обе гигиены одним словарём для /api/status. cfg — конфиг панели (has_dnsmasq)."""
    return {"whitelist": whitelist_stat(bool((cfg or {}).get("has_dnsmasq")), conf, net_file),
            "cleanup": cleanup_stat(stat)}
