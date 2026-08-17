#!/bin/bash
# singbox-watchdog.sh v3 — УМНЫЙ сторож sing-box. Запуск по cron */2.
# Чинит: неактивный sing-box, упавший tun0, потерянный маршрут middleman.
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

# Аварийный режим агента: он владеет маршрутами (middleman -> WAN). Сторож ничего
# не «чинит» (иначе вернул бы default в мёртвый tun0 и убил бы прямой выход) —
# только даёт агенту повторить попытку восстановиться (агент сам держит backoff, §8/F6).
if [ -f /run/vpn-agent-emergency ]; then
    # маркеры двух-провалов начинают с чистого листа после выхода из аварии (F1):
    # иначе довесок с тиков до аварии превратил бы первый же чих в «2-й подряд»
    rm -f /run/singbox-wd.upfail /run/singbox-wd.sbfail
    if [ -x "$AGENT" ]; then "$AGENT" rotate --reason watchdog >> "$LOG" 2>&1; fi
    exit 0
fi

REPAIRED=0

# 0) sing-box активен?
if ! systemctl is-active --quiet sing-box; then
    log "sing-box inactive -> start"; systemctl start sing-box; sleep 5; REPAIRED=1
fi
# 1) tun0 поднят (carrier=1)?
if [ "$(cat /sys/class/net/tun0/carrier 2>/dev/null)" != "1" ]; then
    log "tun0 down/absent -> restart sing-box"; systemctl restart sing-box; sleep 5; REPAIRED=1
fi
# 2) маршрут middleman default на месте?
if ! $IP route show table middleman 2>/dev/null | grep -q '^default dev tun0'; then
    $IP route replace default dev tun0 table middleman && log "restored middleman default route"; REPAIRED=1
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
            log "tun0 egress dead, upstream $UHOST:$UPORT ALIVE -> restart sing-box ($N)"
            systemctl restart sing-box; sleep 5
            $IP route replace default dev tun0 table middleman
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
