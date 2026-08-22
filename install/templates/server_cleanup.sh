#!/bin/bash
# server_cleanup.sh — очистка следов на VPN-сервере
# Cron: 0 */3 * * * (каждые 3 часа)
#
# Что чистит:
#   - journald (логи sing-box, dnsmasq, SSH, microsocks — содержат IP клиентов и dst)
#   - wtmp/btmp (история логинов)
#   - dpkg/apt логи (какие пакеты ставились)
#   - bash history
#   - tmp файлы
#   - dmesg
#   - lastlog
#
# Побочно пишет статистику для панели (сколько освободили, когда) в
# /var/lib/vpn-panel/cleanup-stat.json с накоплением за сутки — карточка статуса
# показывает «за сутки удалено N». Сам стат-файл следом клиента не является.

# ── объём ДО чистки (для панели): журнал (по данным journald) + логи + tmp ─────
# Журнал меряем через journalctl --disk-usage (реально занятое место, любой Storage
# и локаль), а не du: du -b врёт из-за предвыделенных/разреженных journal-файлов.
_du(){ du -bc "$@" 2>/dev/null | tail -1 | awk '{print $1+0}'; }
JBEF=$(journalctl --disk-usage 2>/dev/null)
LOGS=$(_du /var/log/wtmp /var/log/wtmp.db /var/log/btmp /var/log/lastlog \
           /var/log/dpkg.log /var/log/apt/history.log /var/log/apt/term.log \
           /var/log/apt/eipp.log.xz /var/log/alternatives.log /root/.bash_history)
TMPB=$(_du /tmp/*.py /tmp/*.zip /tmp/*.gz /tmp/*.tar /opt/telegram_ws_relay.py)

# ── journald — главный источник следов ────────────────────────────────────────
# --rotate закрывает активный журнал в архив, --vacuum-size=1M удаляет архивы ПО
# РАЗМЕРУ, включая только что закрытый (по времени он моложе секунды и --vacuum-time
# его бы пропустил — из-за этого прежняя метрика показывала «0 Б»).
journalctl --rotate 2>/dev/null
# Важно считать вывод самого vacuum, а не разницу общего disk-usage. После rotate
# journald может сразу создать/предвыделить новый active-файл (обычно 8 MiB): старый
# файл реально удалён, но общий объём «до/после» остаётся тем же и прежняя метрика
# записывала ложный ноль. LC_ALL=C даёт стабильное "freed N" для парсера ниже.
VACOUT=$(LC_ALL=C journalctl --vacuum-size=1M 2>&1)

# ── login history ─────────────────────────────────────────────────────────────
> /var/log/wtmp.db 2>/dev/null
> /var/log/wtmp 2>/dev/null
> /var/log/btmp 2>/dev/null
> /var/log/lastlog 2>/dev/null

# ── apt / dpkg ────────────────────────────────────────────────────────────────
> /var/log/dpkg.log 2>/dev/null
> /var/log/apt/history.log 2>/dev/null
> /var/log/apt/term.log 2>/dev/null
rm -f /var/log/apt/eipp.log.xz 2>/dev/null

# ── alternatives log ──────────────────────────────────────────────────────────
> /var/log/alternatives.log 2>/dev/null

# ── bash history ──────────────────────────────────────────────────────────────
> /root/.bash_history 2>/dev/null
history -c 2>/dev/null

# ── dmesg ─────────────────────────────────────────────────────────────────────
dmesg -C 2>/dev/null

# ── tmp / мусор ───────────────────────────────────────────────────────────────
rm -f /tmp/*.py /tmp/*.zip /tmp/*.gz /tmp/*.tar 2>/dev/null
rm -f /opt/telegram_ws_relay.py 2>/dev/null

# ── whitelist update log (только последняя строка) ────────────────────────────
if [ -f /var/log/ru-whitelist-update.log ]; then
    tail -1 /var/log/ru-whitelist-update.log > /tmp/.wl_last
    mv /tmp/.wl_last /var/log/ru-whitelist-update.log
fi

# ── SSH known_hosts ───────────────────────────────────────────────────────────
> /root/.ssh/known_hosts 2>/dev/null

# ── systemd failed units ─────────────────────────────────────────────────────
systemctl reset-failed 2>/dev/null

# ── объём журнала ПОСЛЕ чистки (для честной дельты) ───────────────────────────
JAFT=$(journalctl --disk-usage 2>/dev/null)

# ── статистика для панели (накопление за сутки) ───────────────────────────────
# freed = освобождённое самим journalctl vacuum + размеры обнулённых/удалённых
# обычных файлов и tmp. JBEF/JAFT оставлены как fallback для старых journalctl,
# которые не печатают итоговое "freed N".
STAT=/var/lib/vpn-panel/cleanup-stat.json
if command -v python3 >/dev/null 2>&1; then
    python3 - "$STAT" "$LOGS" "$TMPB" "$JBEF" "$JAFT" "$VACOUT" 2>/dev/null <<'PY'
import json, os, re, sys, time

def iec(s):
    """'…take up 96.0M in the file system.' / '…занимают 96.0M…' -> байты. Нет числа -> 0."""
    m = re.search(r'([0-9]+(?:\.[0-9]+)?)\s*([KMGTP]?)B?', s or '')
    if not m:
        return 0
    mult = {'': 0, 'K': 1, 'M': 2, 'G': 3, 'T': 4, 'P': 5}[m.group(2)]
    return int(float(m.group(1)) * (1024 ** mult))

path = sys.argv[1]
logs = int(sys.argv[2] or 0)
tmpb = int(sys.argv[3] or 0)
vacuum = sys.argv[6] if len(sys.argv) > 6 else ''
# systemd пишет по одной строке на каждый runtime/persistent journal directory:
# "Vacuuming done, freed 8.0M of archived journals from ...". Складываем их.
matches = re.findall(r'\bfreed\s+([0-9]+(?:\.[0-9]+)?\s*[KMGTP]?B?)\b', vacuum, re.I)
journal = sum(iec(v.upper()) for v in matches) if matches else max(0, iec(sys.argv[4]) - iec(sys.argv[5]))
freed = journal + logs + tmpb
now = time.time()
try:
    d = json.load(open(path))
    runs = []
    for r in d.get("runs", []):
        # Старые [timestamp, total] не теряем при обновлении формата.
        if isinstance(r, list) and len(r) == 2:
            r = {"at": r[0], "freed": r[1]}
        if isinstance(r, dict) and isinstance(r.get("at"), (int, float)) and now - r["at"] < 86400:
            runs.append(r)
except Exception:
    runs = []
runs.append({"at": now, "freed": freed, "journal": journal, "files": logs, "tmp": tmpb})
out = {"last_at": now, "freed_24h": sum(int(r.get("freed", 0)) for r in runs),
       "runs_24h": len(runs), "runs": runs}
os.makedirs(os.path.dirname(path), exist_ok=True)
tmp = path + ".tmp"
json.dump(out, open(tmp, "w"))
os.replace(tmp, path)
PY
fi
