#!/bin/bash
# update-ru-whitelist.sh — обновление белого списка РФ из GitHub.
# Cron: 0 3 * * 0 (воскресенье 03:00). Источник: hxehex/russia-mobile-internet-whitelist.
#
# Репозиторий публикует РАЗНЫЕ списки — скрипт сам находит их (все *.lst/*.conf/*.txt)
# и раскладывает по назначению:
#   • ДОМЕНЫ  -> /etc/dnsmasq.d/ru-whitelist.conf  -> ipset ru_whitelist (hash:ip, наполняется
#                динамически при DNS-резолве клиентом; TTL 2ч);
#   • IP/CIDR -> ipset ru_whitelist_net (hash:net, статически); одиночные IP сворачиваются в
#                диапазоны (collapse), файл /etc/ru_whitelist_net.ipset читает vpn-boot-setup.sh
#                на ребуте (сеть переживает перезагрузку без обращения к GitHub).
# Оба ipset дают одинаковый эффект: dst из белого списка идёт RETURN -> прямой выход РФ-адресом.
set -e

REPO_DIR="/opt/russia-whitelist"
REPO_URL="https://github.com/hxehex/russia-mobile-internet-whitelist"
CONF_FILE="/etc/dnsmasq.d/ru-whitelist.conf"
IPSET_NAME="ru_whitelist"
NET_SET="ru_whitelist_net"
NET_FILE="/etc/ru_whitelist_net.ipset"
LOG="/var/log/ru-whitelist-update.log"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG"; echo "$*"; }

# ── 1. Клонировать / обновить репозиторий ────────────────────────────────────
if [ ! -d "$REPO_DIR/.git" ]; then
    log "Клонирую репозиторий..."
    git clone --depth=1 "$REPO_URL" "$REPO_DIR"
else
    cd "$REPO_DIR"
    OLD_HASH=$(git rev-parse HEAD)
    git fetch --depth=1 origin main 2>/dev/null || git fetch --depth=1 origin master 2>/dev/null
    NEW_HASH=$(git rev-parse FETCH_HEAD)
    if [ "$OLD_HASH" = "$NEW_HASH" ]; then
        log "Нет изменений (commit $OLD_HASH). Пропускаю."
        exit 0
    fi
    git merge --ff-only FETCH_HEAD
    log "Обновлено: $OLD_HASH -> $NEW_HASH"
fi

# ── 2. Разбор: находим все списки, классифицируем строки (домен / IP / CIDR) ──
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
python3 - "$REPO_DIR" "$TMP" <<'PY'
import ipaddress, os, re, sys
REPO, OUT = sys.argv[1], sys.argv[2]
DOM = re.compile(r'^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$')
domains, nets = set(), []
for root, dirs, files in os.walk(REPO):
    dirs[:] = [d for d in dirs if d != '.git']
    for fn in files:
        if not fn.lower().endswith(('.lst', '.conf', '.txt')):
            continue
        for raw in open(os.path.join(root, fn), encoding='utf-8', errors='replace'):
            s = raw.strip()
            if not s or s.startswith('#'):
                continue
            if '/' in s:                                            # CIDR?
                try:
                    nets.append(ipaddress.ip_network(s, strict=False)); continue
                except ValueError:
                    pass
            try:                                                    # одиночный IP?
                nets.append(ipaddress.ip_network(s + '/32', strict=False)); continue
            except ValueError:
                pass
            d = re.sub(r'^www\.', '', s.lower())                    # домен?
            if DOM.match(d):
                domains.add(d)
# домены: выбросить поддомен, если есть родитель (sub.example.com при живом example.com)
dres = []
for d in sorted(domains):
    p = d.split('.')
    if len(p) > 2 and '.'.join(p[1:]) in domains:
        continue
    dres.append(d)
# сети: свернуть перекрытия и смежные в минимальный набор (одиночные IP поглощаются CIDR)
v4 = [n for n in nets if n.version == 4]
collapsed = sorted(ipaddress.collapse_addresses(v4),
                   key=lambda n: (int(n.network_address), n.prefixlen))
open(os.path.join(OUT, 'domains'), 'w', encoding='utf-8').write('\n'.join(dres) + '\n')
open(os.path.join(OUT, 'nets'), 'w', encoding='utf-8').write('\n'.join(str(n) for n in collapsed) + '\n')
PY

DCOUNT=$(grep -c . "$TMP/domains" 2>/dev/null || echo 0)
NCOUNT=$(grep -c . "$TMP/nets" 2>/dev/null || echo 0)
log "Разобрано: доменов $DCOUNT, сетей (IP+CIDR свёрнуты) $NCOUNT"

if [ "$DCOUNT" -lt 50 ]; then
    log "ОШИБКА: слишком мало доменов ($DCOUNT) — похоже, разбор сломался. Прерываю, ничего не меняю."
    exit 1
fi

# ── 3. dnsmasq: конфиг доменов -> ipset ru_whitelist ─────────────────────────
TMP_CONF="$(mktemp)"
{
    echo "# Белый список РФ — прямой выход РФ-адресом (ipset $IPSET_NAME)"
    echo "# Источник: $REPO_URL"
    echo "# Обновлено: $(date '+%Y-%m-%d %H:%M:%S') | доменов: $DCOUNT"
    echo ""
    while read -r domain; do
        [ -n "$domain" ] && echo "ipset=/${domain}/${IPSET_NAME}"
    done < "$TMP/domains"
} > "$TMP_CONF"

if dnsmasq --test --conf-file="$TMP_CONF" 2>&1 | grep -q "syntax check OK"; then
    mv "$TMP_CONF" "$CONF_FILE"
    log "dnsmasq-конфиг обновлён: $CONF_FILE ($DCOUNT доменов)"
else
    log "ОШИБКА синтаксиса dnsmasq — конфиг доменов не применён."
    rm -f "$TMP_CONF"
    exit 1
fi
systemctl reload dnsmasq 2>/dev/null && log "dnsmasq перезагружен (reload)." \
    || { systemctl restart dnsmasq 2>/dev/null && log "dnsmasq перезапущен (restart)."; } || true
ipset flush "$IPSET_NAME" 2>/dev/null && log "ipset $IPSET_NAME сброшен (наполнится по DNS)." || true

# ── 4. IP/CIDR -> ipset ru_whitelist_net (hash:net), атомарно + сохранение ────
if [ "$NCOUNT" -gt 0 ]; then
    set +e
    ipset create "$NET_SET" hash:net family inet hashsize 16384 maxelem 1000000 2>/dev/null
    RESTORE="$(mktemp)"
    {
        echo "create ${NET_SET}_tmp hash:net family inet hashsize 16384 maxelem 1000000"
        sed "s#^#add ${NET_SET}_tmp #" "$TMP/nets"
    } > "$RESTORE"
    ipset destroy "${NET_SET}_tmp" 2>/dev/null
    if ipset restore < "$RESTORE"; then
        ipset swap "${NET_SET}_tmp" "$NET_SET" && ipset destroy "${NET_SET}_tmp" 2>/dev/null
        ipset save "$NET_SET" > "$NET_FILE"
        log "ipset $NET_SET: $NCOUNT сетей применено и сохранено в $NET_FILE."
    else
        ipset destroy "${NET_SET}_tmp" 2>/dev/null
        log "ОШИБКА: ipset restore для $NET_SET не прошёл — старый набор не тронут."
    fi
    rm -f "$RESTORE"
    # Правило RETURN для net-сета навешивает vpn-boot-setup.sh (знает подсеть); дёргаем его,
    # чтобы правило появилось сразу, не дожидаясь ребута. Скрипт идемпотентен.
    [ -x /usr/local/bin/vpn-boot-setup.sh ] && /usr/local/bin/vpn-boot-setup.sh >/dev/null 2>&1
    set -e
else
    log "Списков IP/CIDR в репозитории не найдено — net-набор не трогаю."
fi

log "Готово."
