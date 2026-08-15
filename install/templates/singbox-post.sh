#!/bin/bash
# singbox-post.sh — ExecStartPost для sing-box.
# После старта дождаться tun0 (carrier=1) и вернуть default-маршрут в таблицу middleman.
# Нужно потому, что sing-box работает с auto_route:false и НЕ управляет таблицей middleman:
# при пересоздании tun0 ядро сносит маршрут 'default dev tun0'.
IP=/usr/sbin/ip
for i in $(seq 1 30); do
    [ "$(cat /sys/class/net/tun0/carrier 2>/dev/null)" = "1" ] && break
    sleep 0.3
done
$IP route replace default dev tun0 table middleman
exit 0
