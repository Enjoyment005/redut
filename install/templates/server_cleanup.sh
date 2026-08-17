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
