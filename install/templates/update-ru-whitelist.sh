#!/bin/bash
# Transactional, pinned RU allowlist update.  It fetches exactly three audited
# files, validates provenance/content, stages both consumers, and keeps LKG.
set -euo pipefail

COMMIT="fad3653ebd4b212643774a4d10af3eb33838e4ff"
BASE="https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/$COMMIT"
CONF_FILE="/etc/dnsmasq.d/ru-whitelist.conf"
NET_FILE="/etc/ru_whitelist_net.ipset"
LKG_DIR="/var/lib/vpn-panel/ru-whitelist-lkg"
NET_SET="ru_whitelist_net"
DOMAIN_SET="ru_whitelist"
LOG="/var/log/ru-whitelist-update.log"
TXN_MARK="/var/lib/vpn-panel/ru-whitelist-update.pending"
mkdir -p /var/lib/vpn-panel
PARENT_LOCK_FD="${REDUT_PARENT_LOCK_FD:-}"
if [[ "$PARENT_LOCK_FD" =~ ^[0-9]+$ ]] \
        && [ "$(readlink "/proc/$$/fd/$PARENT_LOCK_FD" 2>/dev/null || true)" = "/run/vpn-agent.lock" ]; then
    # install.sh passed its already-held open file description. Re-proving the
    # inherited fd avoids a generic environment-variable lock bypass.
    flock -n "$PARENT_LOCK_FD" \
        || { echo "RU allowlist: parent lock не подтверждён" >&2; exit 75; }
else
    exec 9>/run/vpn-agent.lock
    flock -n 9 || { echo "RU allowlist: vpn-agent занят, обновление отложено" >&2; exit 75; }
fi
TMP="$(mktemp -d)"
log(){ echo "[$(date '+%F %T')] $*" >> "$LOG"; echo "$*"; }
fsync_paths(){
    python3 - "$@" <<'PY'
import os, sys
for path in sys.argv[1:]:
    if not os.path.exists(path):
        continue
    flags = os.O_RDONLY | (getattr(os, "O_DIRECTORY", 0) if os.path.isdir(path) else 0)
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
PY
}

set_mark(){
    if ! printf '%s\n' "$1" > "$TXN_MARK.tmp"; then return 1; fi
    if ! chmod 600 "$TXN_MARK.tmp"; then return 1; fi
    if ! fsync_paths "$TXN_MARK.tmp"; then return 1; fi
    if ! mv "$TXN_MARK.tmp" "$TXN_MARK"; then return 1; fi
    if ! fsync_paths "$TXN_MARK" "$(dirname "$TXN_MARK")"; then return 1; fi
}
set_exists(){ ipset list -n 2>/dev/null | grep -Fxq "$1"; }
members_hash(){
    ipset save "$1" 2>/dev/null \
        | awk '$1 == "add" { print $3 }' \
        | LC_ALL=C sort \
        | sha256sum | awk '{print $1}'
}
restart_dnsmasq(){
    # SIGHUP/reload does not reread conf-dir.  A checked restart is the only
    # supported generation switch here; require a live, new MainPID before
    # accepting either forward commit or rollback.
    dnsmasq --test >/dev/null 2>&1 || return 1
    local before after
    before="$(systemctl show -p MainPID --value dnsmasq 2>/dev/null || true)"
    systemctl restart dnsmasq || return 1
    systemctl is-active --quiet dnsmasq || return 1
    after="$(systemctl show -p MainPID --value dnsmasq 2>/dev/null || true)"
    [ -n "$after" ] && [ "$after" != "0" ] || return 1
    [ -z "$before" ] || [ "$before" = "0" ] || [ "$after" != "$before" ]
}
restore_files(){
    if [ -f "$LKG_DIR/.had_conf" ]; then
        if ! cp -a "$LKG_DIR/ru-whitelist.conf" "$CONF_FILE"; then return 1; fi
    else
        if ! rm -f -- "$CONF_FILE"; then return 1; fi
    fi
    if [ -f "$LKG_DIR/.had_net" ]; then
        if ! cp -a "$LKG_DIR/ru_whitelist_net.ipset" "$NET_FILE"; then return 1; fi
    else
        if ! rm -f -- "$NET_FILE"; then return 1; fi
    fi
}
rollback_pending(){
    [ -f "$TXN_MARK" ] || return 0
    if [ ! -d "$LKG_DIR" ]; then
        log "ОШИБКА: есть pending RU generation, но LKG отсутствует; нужен оператор"
        return 1
    fi
    if [ ! -f "$LKG_DIR/.old_set_hash" ]; then
        log "ОШИБКА: pending RU generation не имеет old-set hash; нужен оператор"
        return 1
    fi
    if ! old_hash="$(cat "$LKG_DIR/.old_set_hash")"; then
        log "ОШИБКА: old-set hash не читается; marker сохранён"
        return 1
    fi
    # Write rollback intent BEFORE the atomic swap. A crash on either side is
    # resolved idempotently by comparing live/candidate membership hashes.
    if ! set_mark rollback; then
        log "ОШИБКА: rollback marker не записан надёжно"
        return 1
    fi
    if [ "$old_hash" = "ABSENT" ]; then
        if set_exists "$NET_SET" && ! ipset flush "$NET_SET"; then
            log "ОШИБКА: live ipset не очищен; marker сохранён"
            return 1
        fi
    else
        live_hash=""
        if set_exists "$NET_SET" && ! live_hash="$(members_hash "$NET_SET")"; then
            log "ОШИБКА: live ipset hash не читается; marker сохранён"
            return 1
        fi
        if ! set_exists "$NET_SET" || [ "$live_hash" != "$old_hash" ]; then
            candidate_hash=""
            if ! set_exists "${NET_SET}_candidate" \
                    || ! candidate_hash="$(members_hash "${NET_SET}_candidate")" \
                    || [ "$candidate_hash" != "$old_hash" ]; then
                log "ОШИБКА: старое поколение ipset не найдено; marker сохранён"
                return 1
            fi
            if ! ipset swap "${NET_SET}_candidate" "$NET_SET"; then
                log "ОШИБКА: rollback ipset swap не выполнен; marker сохранён"
                return 1
            fi
        fi
    fi
    if ! restore_files; then
        log "ОШИБКА: LKG files не восстановлены; marker сохранён"
        return 1
    fi
    if ! fsync_paths "$CONF_FILE" "$NET_FILE" \
            "$(dirname "$CONF_FILE")" "$(dirname "$NET_FILE")"; then
        log "ОШИБКА: LKG files не синхронизированы; marker сохранён"
        return 1
    fi
    if ! restart_dnsmasq; then
        log "ОШИБКА: LKG dnsmasq не перезапустился; marker сохранён"
        return 1
    fi
    # A killed forward transaction may have reloaded the new domains before it
    # flushed the dynamic set. Reload the old config first, then remove every
    # answer learned under the abandoned generation before clearing the marker.
    if set_exists "$DOMAIN_SET" && ! ipset flush "$DOMAIN_SET"; then
        log "ОШИБКА: dynamic domain ipset после rollback не очищен; marker сохранён"
        return 1
    fi
    # The pending marker is the durable transaction boundary. Keep every
    # rollback aid until its removal has reached disk; otherwise a crash could
    # leave a pending transaction without the old generation hash.
    if ! rm -f -- "$TXN_MARK" "$TXN_MARK.tmp"; then
        log "ОШИБКА: rollback marker не удалён"
        return 1
    fi
    if ! fsync_paths "$(dirname "$TXN_MARK")"; then
        log "ОШИБКА: удаление rollback marker не синхронизировано"
        return 1
    fi
    ipset destroy "${NET_SET}_candidate" 2>/dev/null || true
    if ! rm -f -- "$LKG_DIR/.old_set_hash"; then
        log "ПРЕДУПРЕЖДЕНИЕ: rollback завершён, но LKG metadata не очищена"
    elif ! fsync_paths "$LKG_DIR"; then
        log "ПРЕДУПРЕЖДЕНИЕ: rollback завершён, но очистка LKG metadata не синхронизирована"
    fi
    log "Незавершённое поколение откачено к LKG"
}
cleanup(){
    rollback_pending || true
    rm -r -- "$TMP"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

# A killed previous update leaves a durable marker and the old live ipset under
# the candidate name. Restore it before fetching or overwriting the LKG copy.
rollback_pending || exit 1

fetch(){
    local name="$1" sha="$2"
    curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
        --connect-timeout 5 --max-time 30 --speed-time 10 --speed-limit 1024 \
        "$BASE/$name" -o "$TMP/$name"
    echo "$sha  $TMP/$name" | sha256sum --check --status || {
        log "ОШИБКА provenance: SHA256 $name не совпал"; exit 1;
    }
}
fetch whitelist.txt dfa4ffeec6c97a6feb7c594934d0c8b4e170fadff1d781f0de012ee383832eb9
fetch ipwhitelist.txt 8a3814375701decd9787718fc3ae769187aa4714e2a1b8fa5d96f94ad2bd4da0
fetch cidrwhitelist.txt 149d27a8e3502b95b9a378817854c87af6417c2a9bbf0b17eb8f7affef1f3868

python3 - "$TMP" <<'PY'
import ipaddress, os, re, sys
base = sys.argv[1]
label_re = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

def valid_domain(value):
    if not value or len(value) > 253 or "." not in value:
        return False
    labels = value.split(".")
    for label in labels:
        if not label_re.fullmatch(label):
            return False
        if label.startswith("xn--"):
            # Validate the A-label, not merely the characters.  Invalid IDNA
            # encodings and dnsmasq directive injection stay fail-closed.
            try:
                if label.encode("ascii").decode("idna").encode("idna").decode("ascii").lower() != label:
                    return False
            except UnicodeError:
                return False
    tld = labels[-1]
    return len(tld) >= 2 and (tld.isalpha() or tld.startswith("xn--"))

domains = set()
for raw in open(os.path.join(base, "whitelist.txt"), encoding="utf-8"):
    value = raw.strip().lower().rstrip(".")
    if not value or value.startswith("#"):
        continue
    if not valid_domain(value):
        raise SystemExit("invalid domain input")
    domains.add(value)
if not 800 <= len(domains) <= 2000:
    raise SystemExit("domain count outside audited envelope")

nets = []
for name, single in (("ipwhitelist.txt", True), ("cidrwhitelist.txt", False)):
    for raw in open(os.path.join(base, name), encoding="utf-8"):
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        network = ipaddress.ip_network(value + ("/32" if single else ""), strict=False)
        if network.version != 4 or not network.is_global:
            raise SystemExit("non-global IPv4 in source")
        if network.prefixlen < 12:
            raise SystemExit("network broader than /12")
        nets.append(network)
collapsed = sorted(ipaddress.collapse_addresses(nets),
                   key=lambda n: (int(n.network_address), n.prefixlen))
coverage = sum(n.num_addresses for n in collapsed)
if not 20000 <= len(collapsed) <= 50000 or coverage > 50000000:
    raise SystemExit("network coverage outside audited envelope")

with open(os.path.join(base, "domains"), "w", encoding="utf-8", newline="\n") as out:
    out.write("\n".join(sorted(domains)) + "\n")
with open(os.path.join(base, "nets"), "w", encoding="utf-8", newline="\n") as out:
    out.write("\n".join(map(str, collapsed)) + "\n")
with open(os.path.join(base, "counts"), "w", encoding="ascii") as out:
    out.write("%d %d %d\n" % (len(domains), len(collapsed), coverage))
PY
read -r DCOUNT NCOUNT COVERAGE < "$TMP/counts"
log "Проверено commit=$COMMIT: доменов=$DCOUNT сетей=$NCOUNT coverage=$COVERAGE"

{
    echo "# Redut RU allowlist; pinned commit $COMMIT; domains $DCOUNT"
    while IFS= read -r domain; do echo "ipset=/$domain/$DOMAIN_SET"; done < "$TMP/domains"
} > "$TMP/dnsmasq.conf"
{
    echo "create $NET_SET hash:net family inet hashsize 65536 maxelem 1000000"
    while IFS= read -r network; do echo "add $NET_SET $network"; done < "$TMP/nets"
} > "$TMP/net.ipset"
{
    echo "create ${NET_SET}_candidate hash:net family inet hashsize 65536 maxelem 1000000"
    while IFS= read -r network; do echo "add ${NET_SET}_candidate $network"; done < "$TMP/nets"
} > "$TMP/candidate.ipset"

dnsmasq --test --conf-file="$TMP/dnsmasq.conf" >/dev/null 2>&1 || {
    log "ОШИБКА: dnsmasq rejected staged config"; exit 1;
}

ipset destroy "${NET_SET}_candidate" 2>/dev/null || true
ipset restore < "$TMP/candidate.ipset" || {
    ipset destroy "${NET_SET}_candidate" 2>/dev/null || true
    log "ОШИБКА: ipset rejected staged networks"; exit 1;
}

mkdir -p "$LKG_DIR"
chmod 700 "$LKG_DIR"
rm -f -- "$LKG_DIR/.had_conf" "$LKG_DIR/.had_net"
if [ -f "$CONF_FILE" ]; then
    cp -a "$CONF_FILE" "$LKG_DIR/ru-whitelist.conf"
    touch "$LKG_DIR/.had_conf"
fi
if [ -f "$NET_FILE" ]; then
    cp -a "$NET_FILE" "$LKG_DIR/ru_whitelist_net.ipset"
    touch "$LKG_DIR/.had_net"
fi
if set_exists "$NET_SET"; then
    members_hash "$NET_SET" > "$LKG_DIR/.old_set_hash"
else
    printf 'ABSENT\n' > "$LKG_DIR/.old_set_hash"
fi
chmod 600 "$LKG_DIR/.old_set_hash"
fsync_paths "$LKG_DIR/ru-whitelist.conf" "$LKG_DIR/ru_whitelist_net.ipset" \
    "$LKG_DIR/.had_conf" "$LKG_DIR/.had_net" "$LKG_DIR/.old_set_hash" "$LKG_DIR"
install -m 0644 "$TMP/dnsmasq.conf" "$CONF_FILE.candidate"
install -m 0600 "$TMP/net.ipset" "$NET_FILE.candidate"
fsync_paths "$CONF_FILE.candidate" "$NET_FILE.candidate" \
    "$(dirname "$CONF_FILE")" "$(dirname "$NET_FILE")"
set_mark prepared
ipset create "$NET_SET" hash:net family inet hashsize 65536 maxelem 1000000 2>/dev/null || true
ipset swap "${NET_SET}_candidate" "$NET_SET"
set_mark ipset_swapped
mv "$CONF_FILE.candidate" "$CONF_FILE"
mv "$NET_FILE.candidate" "$NET_FILE"
fsync_paths "$CONF_FILE" "$NET_FILE" "$(dirname "$CONF_FILE")" "$(dirname "$NET_FILE")"
set_mark files_installed
if ! restart_dnsmasq; then
    log "ОШИБКА: dnsmasq checked restart failed; generation will be rolled back"; exit 1
fi
# Dynamic domain answers belong to the previous bundle. Flush them while the
# transaction is still recoverable; an existing set that cannot be flushed is
# a failed commit, not a best-effort warning.
if set_exists "$DOMAIN_SET"; then
    ipset flush "$DOMAIN_SET" || {
        log "ОШИБКА: dynamic domain ipset не очищен; generation will be rolled back"; exit 1;
    }
fi
# Commit becomes durable only after the pending marker deletion and its parent
# directory fsync. Rollback metadata is deliberately retained until then.
if ! rm -f -- "$TXN_MARK" "$TXN_MARK.tmp"; then
    log "ОШИБКА: commit marker не удалён; generation will be rolled back"; exit 1
fi
if ! fsync_paths "$(dirname "$TXN_MARK")"; then
    log "ОШИБКА: удаление commit marker не синхронизировано; generation will be rolled back"; exit 1
fi
if ! rm -f -- "$LKG_DIR/.old_set_hash"; then
    log "ПРЕДУПРЕЖДЕНИЕ: commit завершён, но LKG metadata не очищена"
elif ! fsync_paths "$LKG_DIR"; then
    log "ПРЕДУПРЕЖДЕНИЕ: commit завершён, но очистка LKG metadata не синхронизирована"
fi
ipset destroy "${NET_SET}_candidate" 2>/dev/null || true
log "Применено атомарно; boot не запускался, чужие правила не затронуты."
