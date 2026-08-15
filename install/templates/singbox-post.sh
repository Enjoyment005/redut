#!/bin/bash
# singbox-post.sh — ExecStartPost для sing-box.
# После старта дождаться tun0 (carrier=1) и вернуть default-маршрут в таблицу middleman.
# Нужно потому, что sing-box работает с auto_route:false и НЕ управляет таблицей middleman:
# при пересоздании tun0 ядро сносит маршрут 'default dev tun0'.
#
# ИСКЛЮЧЕНИЕ (15.08, снос №5): пока узел в аварийном режиме / прямом выходе (флаг
# /run/vpn-agent-emergency — его ставит агент или boot-скрипт при пустом канале), маршрутом
# владеет агент: middleman смотрит в WAN, а tun0 без рабочего upstream — чёрная дыра.
# Раньше любой рестарт sing-box в аварии (self-heal, краш, переустановка) возвращал default в
# мёртвый tun0, и клиенты сидели без сети до следующего тика сторожа (до 2 мин).
IP=/usr/sbin/ip
for i in $(seq 1 30); do
    [ "$(cat /sys/class/net/tun0/carrier 2>/dev/null)" = "1" ] && break
    sleep 0.3
done
if [ -f /run/vpn-agent-emergency ]; then
    echo "singbox-post: аварийный режим / прямой выход — маршрут middleman не трогаю (агент вернёт tun0 сам)"
    exit 0
fi
$IP route replace default dev tun0 table middleman
exit 0
