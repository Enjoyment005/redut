#!/bin/bash
# Generic reference boot reconciler. install.sh renders the same policy with
# node-specific values; this template reads /etc/vpn-panel/node.env.
set -eu
. /etc/vpn-panel/node.env
IPTABLES=/usr/sbin/iptables

if ! /usr/sbin/ip link show wg0 >/dev/null 2>&1; then
    systemctl start wg-quick@wg0 2>/dev/null || wg-quick up wg0 2>/dev/null || true
fi
ipset create ru_whitelist hash:ip timeout 7200 2>/dev/null || true
if [ -f /etc/ru_whitelist_net.ipset ]; then
    ipset create ru_whitelist_net hash:net family inet hashsize 16384 maxelem 1000000 2>/dev/null || true
    ipset flush ru_whitelist_net
    sed 's/^add [^ ]* /add ru_whitelist_net /' /etc/ru_whitelist_net.ipset | ipset restore -!
fi

$IPTABLES -t mangle -N REDUT_PREROUTING 2>/dev/null || true
$IPTABLES -t mangle -F REDUT_PREROUTING
$IPTABLES -t mangle -C PREROUTING -s "$SUBNET" -j REDUT_PREROUTING 2>/dev/null || \
    $IPTABLES -t mangle -I PREROUTING 1 -s "$SUBNET" -j REDUT_PREROUTING
$IPTABLES -t mangle -A REDUT_PREROUTING -s "$SUBNET" -m set --match-set ru_whitelist dst -j RETURN
if ipset list -n ru_whitelist_net >/dev/null 2>&1; then
    $IPTABLES -t mangle -A REDUT_PREROUTING -s "$SUBNET" -m set --match-set ru_whitelist_net dst -j RETURN
fi
$IPTABLES -t mangle -A REDUT_PREROUTING -s "$SUBNET" -d "$SUBNET" -j RETURN
$IPTABLES -t mangle -A REDUT_PREROUTING -s "$SUBNET" -d "$SERVER_IP/32" -j RETURN
$IPTABLES -t mangle -A REDUT_PREROUTING -s "$SUBNET" -j MARK --set-mark 0x64

$IPTABLES -t nat -C POSTROUTING -s "$SUBNET" -o "$WAN" -j MASQUERADE 2>/dev/null || \
    $IPTABLES -t nat -A POSTROUTING -s "$SUBNET" -o "$WAN" -j MASQUERADE
$IPTABLES -C FORWARD -i wg0 -j ACCEPT 2>/dev/null || $IPTABLES -A FORWARD -i wg0 -j ACCEPT
$IPTABLES -C FORWARD -o wg0 -j ACCEPT 2>/dev/null || $IPTABLES -A FORWARD -o wg0 -j ACCEPT

for _i in $(seq 1 30); do /usr/sbin/ip link show tun0 >/dev/null 2>&1 && break; sleep 1; done
if [ -f /var/lib/vpn-panel/emergency.intent ] || [ -z "${UP_HOST:-}" ]; then
    /usr/sbin/ip route replace default via "$GW" dev "$WAN" table middleman
    mkdir -p /run /var/lib/vpn-panel
    if [ ! -f /var/lib/vpn-panel/emergency.intent ]; then
        ( umask 077; date '+%F %T boot: no upstream' > /var/lib/vpn-panel/emergency.intent )
    fi
    cp /var/lib/vpn-panel/emergency.intent /run/vpn-agent-emergency
else
    /usr/sbin/ip route replace default dev tun0 table middleman
    /usr/sbin/ip route replace "$UP_HOST/32" via "$GW" dev "$WAN"
fi
/usr/sbin/ip route replace "$SUBNET" dev wg0 table middleman
/usr/sbin/ip rule del fwmark 0x64 2>/dev/null || true
/usr/sbin/ip rule add fwmark 0x64 lookup middleman priority 100
sysctl -q net.ipv4.ip_forward=1
