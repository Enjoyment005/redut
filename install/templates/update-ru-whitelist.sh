#!/bin/bash
# update-ru-whitelist.sh - auto-update RU whitelist from GitHub
# Cron: 0 3 * * 0 (every Sunday at 03:00)
set -e

REPO_DIR="/opt/russia-whitelist"
CONF_FILE="/etc/dnsmasq.d/ru-whitelist.conf"
IPSET_NAME="ru_whitelist"
LOG="/var/log/ru-whitelist-update.log"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG"; echo "$*"; }

# 1. Clone or update repo
if [ ! -d "$REPO_DIR/.git" ]; then
    log "Cloning repository..."
    git clone --depth=1 https://github.com/hxehex/russia-mobile-internet-whitelist "$REPO_DIR"
else
    log "Checking for updates..."
    cd "$REPO_DIR"
    OLD_HASH=$(git rev-parse HEAD)
    git fetch --depth=1 origin main 2>/dev/null || git fetch --depth=1 origin master 2>/dev/null
    NEW_HASH=$(git rev-parse FETCH_HEAD)
    if [ "$OLD_HASH" = "$NEW_HASH" ]; then
        log "No changes (commit $OLD_HASH). Skipping."
        exit 0
    fi
    git merge --ff-only FETCH_HEAD
    log "Updated: $OLD_HASH -> $NEW_HASH"
fi

# 2. Parse domains from repo files
log "Parsing domains..."
DOMAINS=$(
    find "$REPO_DIR" -type f \( -name "*.lst" -o -name "*.conf" -o -name "*.txt" \) \
    | xargs grep -h -oP '[a-z0-9][a-z0-9.-]+\.[a-z]{2,}' 2>/dev/null \
    | grep -v '^#' \
    | sed 's/^www\.//' \
    | sort -u
)

COUNT=$(echo "$DOMAINS" | grep -c .)
log "Found domains: $COUNT"

if [ "$COUNT" -lt 50 ]; then
    log "ERROR: too few domains ($COUNT), aborting."
    exit 1
fi

# 3. Deduplicate subdomains (remove sub.example.com if example.com exists)
DEDUPED=$(echo "$DOMAINS" | python3 -c '
import sys
domains = set(sys.stdin.read().strip().splitlines())
result = []
for d in sorted(domains):
    parts = d.split(".")
    if len(parts) > 2 and ".".join(parts[1:]) in domains:
        continue
    result.append(d)
print("\n".join(result))
')
DEDUPED_COUNT=$(echo "$DEDUPED" | grep -c .)
log "After dedup: $DEDUPED_COUNT domains"

# 4. Generate new dnsmasq config
TMP_CONF=$(mktemp)
{
    echo "# RU whitelist - direct exit via Russian IP"
    echo "# Source: github.com/hxehex/russia-mobile-internet-whitelist"
    echo "# Updated: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "# Domains: $DEDUPED_COUNT"
    echo ""
    echo "$DEDUPED" | while read -r domain; do
        echo "ipset=/${domain}/${IPSET_NAME}"
    done
} > "$TMP_CONF"

# 5. Syntax check and apply
if dnsmasq --test --conf-file="$TMP_CONF" 2>&1 | grep -q "syntax check OK"; then
    mv "$TMP_CONF" "$CONF_FILE"
    log "Config updated: $CONF_FILE ($DEDUPED_COUNT domains)"
else
    log "ERROR: dnsmasq syntax error, config not applied."
    rm -f "$TMP_CONF"
    exit 1
fi

# 6. Reload dnsmasq
systemctl reload dnsmasq 2>/dev/null && log "dnsmasq reloaded." \
    || { systemctl restart dnsmasq && log "dnsmasq restarted."; }

# 7. Flush old ipset - new IPs come via DNS queries
ipset flush "$IPSET_NAME" 2>/dev/null && log "ipset $IPSET_NAME flushed." || true

log "Done."
