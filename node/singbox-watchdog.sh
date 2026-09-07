#!/bin/bash
# REDUT_BASE_CONTRACT=2
# singbox-watchdog.sh v3 — УМНЫЙ сторож sing-box. Запуск по cron */2.
# Наблюдает: неактивный sing-box, упавший tun0, потерянный маршрут middleman.
# Сам сеть не меняет: единственный writer — vpn-agent под /run/vpn-agent.lock.
# УМНО: если выход через tun0 мёртв, СНАЧАЛА проверяет внешний upstream-прокси
#       (адрес/креды читаются из /etc/sing-box/config.json автоматически):
#         - upstream ЖИВ, а tun0 нет  -> виноват sing-box -> рестарт
#         - upstream МЁРТВ            -> рестарт не поможет -> зовём vpn-agent rotate
#           (машина состояний §8: RETUNE/ротация/докупка/авария под своим flock+лимитами)
# Аварийный режим агента (флаг /run/vpn-agent-emergency): сторож НЕ трогает
# sing-box/tun0/маршрут (агент направил middleman в WAN), только даёт повторить.
# Универсален: работает на любом сервере (RU, Артур, ...) без правок.
# Лог: /var/log/singbox-watchdog.log
LOG=/var/log/singbox-watchdog.log
CFG=/etc/sing-box/config.json
IP=/usr/sbin/ip
AGENT=/usr/local/bin/vpn-agent
ts(){ date '+%F %T'; }
log(){ echo "$(ts) $*" >> "$LOG"; }
is_ip(){ echo "$1" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; }
# лог не чаще раза в час по метке
throttled_log(){ # $1=stamp-файл $2=сообщение
    local st="/run/singbox-wd.$1"
    if [ ! -f "$st" ] || [ $(( $(date +%s) - $(stat -c %Y "$st" 2>/dev/null || echo 0) )) -ge 3600 ]; then
        log "$2"; touch "$st"
    fi
}

# Read-only proof of the normal client policy path.  Every mutation remains in
# vpn-agent under /run/vpn-agent.lock; this observer merely makes rule-only and
# effective-FIB drift reachable by the reconciler.
policy_path_ok(){
    local defaults rules marked count
    defaults="$($IP -4 route show table middleman default 2>/dev/null)" || return 1
    printf '%s\n' "$defaults" | awk '
        $1 == "default" {
            n++; dev=""; devs=0; vias=0; nexthops=0
            for (i=1; i<=NF; i++) {
                if ($i == "dev") { devs++; dev=$(i+1) }
                if ($i == "via") vias++
                if ($i == "nexthop") nexthops++
            }
            if (devs == 1 && dev == "tun0" && vias == 0 && nexthops == 0) good++
        }
        END { exit !(n == 1 && good == 1) }
    ' || return 1

    rules="$($IP -4 rule show 2>/dev/null)" || return 1
    count="$(printf '%s\n' "$rules" | awk '
        $1 == "100:" && $2 == "from" && $3 == "all" && $4 == "fwmark" &&
        ($5 == "0x64" || $5 == "0x64/0xffffffff") &&
        $6 == "lookup" && $7 == "middleman" && NF == 7 { n++ }
        END { print n+0 }
    ')"
    [ "$count" = "1" ] || return 1

    marked="$($IP -4 route get 8.8.8.8 mark 0x64 2>/dev/null)" || return 1
    printf '%s\n' "$marked" | awk '
        NR == 1 {
            dev=""; table=""; devs=0; tables=0
            for (i=1; i<=NF; i++) {
                if ($i == "dev") { devs++; dev=$(i+1) }
                if ($i == "table") { tables++; table=$(i+1) }
            }
            ok=(devs == 1 && dev == "tun0" && tables == 1 && table == "middleman")
        }
        END { exit !ok }
    '
}

# Allows the regression suite to source and exercise only the read-only proof.
if [ "${REDUT_WATCHDOG_SOURCE_ONLY:-0}" = "1" ]; then
    return 0 2>/dev/null || exit 0
fi

# Аварийный режим агента: он владеет маршрутами (middleman -> WAN). Сторож ничего
# не «чинит» (иначе вернул бы default в мёртвый tun0 и убил бы прямой выход) —
# только даёт агенту повторить попытку восстановиться (агент сам держит backoff, §8/F6).
if [ -f /run/vpn-agent-emergency ] || [ -f /var/lib/vpn-panel/emergency.intent ]; then
    # маркеры двух-провалов начинают с чистого листа после выхода из аварии (F1):
    # иначе довесок с тиков до аварии превратил бы первый же чих в «2-й подряд»
    rm -f /run/singbox-wd.upfail /run/singbox-wd.sbfail
    if [ -x "$AGENT" ]; then "$AGENT" rotate --reason watchdog >> "$LOG" 2>&1; fi
    exit 0
fi

REPAIRED=0

# 0) sing-box активен?
if ! systemctl is-active --quiet sing-box; then
    log "sing-box inactive -> vpn-agent reconcile"
    [ -x "$AGENT" ] && "$AGENT" rotate --reason watchdog >> "$LOG" 2>&1 || true
    exit 0
fi
# 1) tun0 поднят (carrier=1)?
if [ "$(cat /sys/class/net/tun0/carrier 2>/dev/null)" != "1" ]; then
    log "tun0 down/absent -> vpn-agent reconcile"
    [ -x "$AGENT" ] && "$AGENT" rotate --reason watchdog >> "$LOG" 2>&1 || true
    exit 0
fi
# Route ownership belongs to vpn-agent. Watchdog proves the exact singleton
# default, fwmark rule and effective marked FIB, then only asks the agent to
# reconcile; it never races a panel click by writing middleman directly.
if ! policy_path_ok; then
    log "middleman policy-path drift -> vpn-agent rotate"
    if [ -x "$AGENT" ]; then "$AGENT" rotate --reason watchdog >> "$LOG" 2>&1; fi
    exit 0
fi
# 3) реальный выход через tun0
OUT=$(curl -s --max-time 10 --interface tun0 https://api.ipify.org 2>/dev/null)
if ! is_ip "$OUT"; then
    # читаем upstream socks из config
    UP=$(python3 - "$CFG" <<'PY'
import json,sys
try:
    c=json.load(open(sys.argv[1]))
    for o in c.get("outbounds",[]):
        if o.get("type")=="socks":
            print(o.get("server",""),o.get("server_port",""),o.get("username",""),o.get("password","")); break
except Exception: pass
PY
)
    set -- $UP; UHOST="$1"; UPORT="$2"; UUSER="$3"; UPASS="$4"
    UPOUT=""
    if [ -n "$UHOST" ] && [ -n "$UPORT" ]; then
        UPOUT=$(curl -s --max-time 10 --socks5-hostname "$UHOST:$UPORT" --proxy-user "$UUSER:$UPASS" https://api.ipify.org 2>/dev/null)
    fi
    if is_ip "$UPOUT"; then
        # F2 (ревью 1.3.0): «прокси жив, tun0 мёртв» — рестарт может НЕ лечить
        # (sing-box не поднимает tun0). Раньше сторож молча рестартил каждые 2 мин
        # вечно и агента не звал — предохранитель F2 в rotate голодал. Считаем
        # безуспешные попытки; с 3-й подряд зовём агента (файл-счётчик в /run,
        # сбрасывается ребутом и любым здоровым тиком).
        N=$(cat /run/singbox-wd.sbfail 2>/dev/null || echo 0); N=$((N+1))
        echo "$N" > /run/singbox-wd.sbfail
        if [ "$N" -ge 3 ] && [ -x "$AGENT" ]; then
            log "tun0 egress dead, upstream $UHOST:$UPORT ALIVE, рестарт не лечит ($N подряд) -> vpn-agent rotate (F2)"
            "$AGENT" rotate --reason watchdog >> "$LOG" 2>&1
        else
            log "tun0 egress dead, upstream $UHOST:$UPORT ALIVE -> vpn-agent reconcile ($N)"
            "$AGENT" rotate --reason watchdog >> "$LOG" 2>&1 || true
        fi
        rm -f /run/singbox-wd.upfail          # виноват был sing-box, не upstream
        REPAIRED=1
    else
        # upstream МЁРТВ -> рестарт sing-box не поможет. F1 (1.3.0): требуем 2 ПОДРЯД
        # провала (маркер в /run: сбрасывается ребутом и любым здоровым тиком) —
        # единичный сетевой чих не должен дёргать ротацию. Цена: обнаружение
        # реального обрыва замедляется на ~2 мин (осознанно).
        if [ ! -f /run/singbox-wd.upfail ]; then
            touch /run/singbox-wd.upfail
            log "tun0 egress dead И upstream $UHOST:$UPORT недоступен — жду подтверждения следующим тиком (F1)"
        elif [ -x "$AGENT" ]; then
            # 2-й провал подряд: зовём агента (§1, §8) — под своим flock он проведёт
            # диагностику по порядку и сам решит RETUNE/ротация/докупка/авария
            # (сеть сервера мертва -> он НЕ покупает, только алерт). Лимиты держит сам.
            log "tun0 egress dead И upstream $UHOST:$UPORT НЕДОСТУПЕН (2-й тик подряд) -> vpn-agent rotate (§8)"
            "$AGENT" rotate --reason watchdog >> "$LOG" 2>&1
        else
            throttled_log upwarn "tun0 egress dead И upstream $UHOST:$UPORT НЕДОСТУПЕН, а vpn-agent не установлен -> пропускаю"
        fi
        REPAIRED=1
    fi
else
    rm -f /run/singbox-wd.upfail /run/singbox-wd.sbfail   # здоровый тик сбрасывает маркеры (F1/F2)
fi
# Heartbeat 'ok' раз в час (только если всё здорово и ремонта не было)
if [ "$REPAIRED" = "0" ]; then
    throttled_log ok "ok (egress=$OUT)"
fi
exit 0
