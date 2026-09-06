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
TMP="$(mktemp -d)"
cleanup(){ rm -r -- "$TMP"; }
trap cleanup EXIT
log(){ echo "[$(date '+%F %T')] $*" >> "$LOG"; echo "$*"; }

fetch(){
    local name="$1" sha="$2"
    curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
        "$BASE/$name" -o "$TMP/$name"
    echo "$sha  $TMP/$name" | sha256sum --check --status || {
        log "ОШИБКА provenance: SHA256 $name не совпал"; exit 1;
    }
}
fetch whitelist.txt 13e0e92b7ee3c8328f2ff48c9dee655f71a5e211ba745638c9482b666d2bce3e
fetch ipwhitelist.txt 4884f8165ef6059432194166536c74201227473aa5ac25abb7dddecd5df7bac0
fetch cidrwhitelist.txt c8abba3ab5e03a667d5427f9b03b3f79510a7b0e6429cc0af8fc37b4f233349f

python3 - "$TMP" <<'PY'
import ipaddress, os, re, sys
base = sys.argv[1]
domain_re = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
domains = set()
for raw in open(os.path.join(base, "whitelist.txt"), encoding="utf-8"):
    value = raw.strip().lower().rstrip(".")
    if not value or value.startswith("#"):
        continue
    if not domain_re.fullmatch(value):
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
[ ! -f "$CONF_FILE" ] || cp -a "$CONF_FILE" "$LKG_DIR/ru-whitelist.conf"
[ ! -f "$NET_FILE" ] || cp -a "$NET_FILE" "$LKG_DIR/ru_whitelist_net.ipset"
install -m 0644 "$TMP/dnsmasq.conf" "$CONF_FILE.candidate"
install -m 0600 "$TMP/net.ipset" "$NET_FILE.candidate"
mv "$CONF_FILE.candidate" "$CONF_FILE"
mv "$NET_FILE.candidate" "$NET_FILE"
if ! systemctl reload dnsmasq; then
    [ ! -f "$LKG_DIR/ru-whitelist.conf" ] || cp -a "$LKG_DIR/ru-whitelist.conf" "$CONF_FILE"
    [ ! -f "$LKG_DIR/ru_whitelist_net.ipset" ] || cp -a "$LKG_DIR/ru_whitelist_net.ipset" "$NET_FILE"
    systemctl reload dnsmasq 2>/dev/null || true
    ipset destroy "${NET_SET}_candidate" 2>/dev/null || true
    log "ОШИБКА: dnsmasq reload failed; files rolled back"; exit 1
fi
ipset create "$NET_SET" hash:net family inet hashsize 65536 maxelem 1000000 2>/dev/null || true
ipset swap "${NET_SET}_candidate" "$NET_SET"
ipset destroy "${NET_SET}_candidate" 2>/dev/null || true
ipset flush "$DOMAIN_SET" 2>/dev/null || true
log "Применено атомарно; boot не запускался, чужие правила не затронуты."
