#!/bin/bash
# server_cleanup.sh — bounded cleanup of Redut-owned artifacts only.
# Cron: 0 */3 * * *
#
# This job deliberately does NOT touch journald, login/package history,
# /root/.ssh/known_hosts, foreign /opt files, arbitrary /tmp archives, dmesg or
# systemd failed-unit state. Those are host/operator evidence, not Redut data.
set -u

STATE_DIR=/var/lib/vpn-panel
STAT="$STATE_DIR/cleanup-stat.json"
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR" 2>/dev/null || true

freed=0
for root in /tmp /var/tmp; do
    [ -d "$root" ] || continue
    n=$(find "$root" -maxdepth 1 -type f -user root -mtime +1 \
        \( -name 'redut-*.tmp' -o -name 'vpn-panel-*.tmp' \
           -o -name '.redut-*.tmp' -o -name '.vpn-panel-*.tmp' \) \
        -printf '%s\n' 2>/dev/null | awk '{s+=$1} END{print s+0}')
    freed=$((freed + n))
    find "$root" -maxdepth 1 -type f -user root -mtime +1 \
        \( -name 'redut-*.tmp' -o -name 'vpn-panel-*.tmp' \
           -o -name '.redut-*.tmp' -o -name '.vpn-panel-*.tmp' \) \
        -delete 2>/dev/null || true
done

# Keep a bounded diagnostic tail. Atomic replace avoids readers observing a
# truncated file; active transaction journals and *.pending markers are never
# candidates for cleanup.
for log in /var/log/singbox-watchdog.log /var/log/ru-whitelist-update.log; do
    [ -f "$log" ] || continue
    tmp="${log}.redut-cleanup.$$"
    if tail -n 200 "$log" > "$tmp" 2>/dev/null; then
        chmod --reference="$log" "$tmp" 2>/dev/null || chmod 600 "$tmp" 2>/dev/null || true
        chown --reference="$log" "$tmp" 2>/dev/null || true
        mv -f -- "$tmp" "$log"
    else
        rm -f -- "$tmp"
    fi
done

if command -v python3 >/dev/null 2>&1; then
    python3 - "$STAT" "$freed" <<'PY'
import json, os, sys, tempfile, time

path, freed = sys.argv[1], int(sys.argv[2] or 0)
now = time.time()
try:
    with open(path, encoding="utf-8") as source:
        old = json.load(source)
except (OSError, ValueError, TypeError):
    old = {}
runs = [item for item in (old.get("runs") or [])
        if isinstance(item, dict) and isinstance(item.get("at"), (int, float))
        and now - item["at"] < 86400]
runs.append({"at": now, "freed": freed, "scope": "redut-owned"})
out = {"last_at": now, "freed_24h": sum(int(item.get("freed", 0)) for item in runs),
       "runs_24h": len(runs), "runs": runs, "scope": "redut-owned"}
parent = os.path.dirname(path)
fd, tmp = tempfile.mkstemp(prefix=".cleanup-stat.", dir=parent)
try:
    os.chmod(tmp, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as target:
        fd = -1
        json.dump(out, target, separators=(",", ":"))
        target.write("\n")
        target.flush()
        os.fsync(target.fileno())
    os.replace(tmp, path)
finally:
    if fd >= 0:
        os.close(fd)
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
PY
fi
