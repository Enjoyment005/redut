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

# ── объём ДО чистки (для панели): каталоги журнала + логи + tmp ───────────────
_du(){ du -bc "$@" 2>/dev/null | tail -1 | awk '{print $1+0}'; }
J0=$(_du /var/log/journal /run/log/journal)
LOGS=$(_du /var/log/wtmp /var/log/wtmp.db /var/log/btmp /var/log/lastlog \
           /var/log/dpkg.log /var/log/apt/history.log /var/log/apt/term.log \
           /var/log/apt/eipp.log.xz /var/log/alternatives.log /root/.bash_history)
TMPB=$(_du /tmp/*.py /tmp/*.zip /tmp/*.gz /tmp/*.tar /opt/telegram_ws_relay.py)

# ── journald — главный источник следов ────────────────────────────────────────
journalctl --rotate 2>/dev/null
journalctl --vacuum-time=1s 2>/dev/null

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

# ── статистика для панели (накопление за сутки) ───────────────────────────────
J1=$(_du /var/log/journal /run/log/journal)
FREED=$(( (J0 > J1 ? J0 - J1 : 0) + LOGS + TMPB ))
STAT=/var/lib/vpn-panel/cleanup-stat.json
if command -v python3 >/dev/null 2>&1; then
    python3 - "$STAT" "$FREED" 2>/dev/null <<'PY'
import json, os, sys, time
path, freed = sys.argv[1], int(sys.argv[2] or 0)
now = time.time()
try:
    d = json.load(open(path))
    runs = [r for r in d.get("runs", []) if isinstance(r, list) and len(r) == 2 and now - r[0] < 86400]
except Exception:
    runs = []
runs.append([now, freed])
out = {"last_at": now, "freed_24h": sum(int(r[1]) for r in runs), "runs_24h": len(runs), "runs": runs}
os.makedirs(os.path.dirname(path), exist_ok=True)
tmp = path + ".tmp"
json.dump(out, open(tmp, "w"))
os.replace(tmp, path)
PY
fi
