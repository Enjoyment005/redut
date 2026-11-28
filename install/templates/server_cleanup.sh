#!/bin/bash
# REDUT_BASE_CONTRACT=3
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
exec 9>"$STATE_DIR/cleanup.lock" || exit 1
flock -n 9 || exit 0

tmp_bytes=0
log_bytes=0
for root in /tmp /var/tmp; do
    [ -d "$root" ] || continue
    while IFS= read -r -d '' file; do
        n=$(stat -c '%s' -- "$file" 2>/dev/null) || continue
        if rm -- "$file" 2>/dev/null; then
            tmp_bytes=$((tmp_bytes + n))
        fi
    done < <(find "$root" -maxdepth 1 -type f -user root -mtime +1 \
        \( -name 'redut-*.tmp' -o -name 'vpn-panel-*.tmp' \
           -o -name '.redut-*.tmp' -o -name '.vpn-panel-*.tmp' \) \
        -print0 2>/dev/null)
done

# Keep a bounded diagnostic tail. Atomic replace avoids readers observing a
# truncated file; active transaction journals and *.pending markers are never
# candidates for cleanup.
for log in /var/log/singbox-watchdog.log /var/log/ru-whitelist-update.log; do
    [ -f "$log" ] || continue
    before=$(stat -c '%s' -- "$log" 2>/dev/null) || continue
    tmp="${log}.redut-cleanup.$$"
    if tail -n 200 "$log" > "$tmp" 2>/dev/null; then
        after=$(stat -c '%s' -- "$tmp" 2>/dev/null) || { rm -f -- "$tmp"; continue; }
        if [ "$before" -le "$after" ]; then
            rm -f -- "$tmp"
            continue
        fi
        chmod --reference="$log" "$tmp" 2>/dev/null || chmod 600 "$tmp" 2>/dev/null || true
        chown --reference="$log" "$tmp" 2>/dev/null || true
        if mv -f -- "$tmp" "$log"; then
            log_bytes=$((log_bytes + before - after))
        else
            rm -f -- "$tmp"
        fi
    else
        rm -f -- "$tmp"
    fi
done

if command -v python3 >/dev/null 2>&1; then
    python3 - "$STAT" "$tmp_bytes" "$log_bytes" <<'PY'
import json, math, os, sys, tempfile, time

path = sys.argv[1]
tmp_bytes, log_bytes = (int(value or 0) for value in sys.argv[2:4])
freed = tmp_bytes + log_bytes
now = time.time()
try:
    with open(path, encoding="utf-8") as source:
        old = json.load(source)
except (OSError, ValueError, TypeError):
    old = {}
runs = []
history = old.get("runs") if isinstance(old, dict) else None
for item in history if isinstance(history, list) else []:
    if isinstance(item, list) and len(item) == 2:
        item = {"at": item[0], "freed": item[1]}
    if not isinstance(item, dict):
        continue
    at, size = item.get("at"), item.get("freed")
    if (type(at) in (int, float) and math.isfinite(at) and now - 86400 < at <= now + 300
            and type(size) in (int, float) and math.isfinite(size) and size >= 0):
        runs.append(item)
runs.append({"at": now, "freed": freed, "files": log_bytes, "tmp": tmp_bytes,
             "scope": "redut-owned", "accounting_version": 2})
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
