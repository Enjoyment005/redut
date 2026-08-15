#!/bin/bash
# VPN boot setup (subnet 10.8.0.0/24, upstream 203.0.113.10)
ipset create ru_whitelist hash:ip timeout 7200 2>/dev/null || true
iptables -t mangle -F PREROUTING
iptables -t mangle -A PREROUTING -s 10.8.0.0/24 -m set --match-set ru_whitelist dst -j RETURN
iptables -t mangle -A PREROUTING -s 10.8.0.0/24 -j MARK --set-mark 0x64
iptables -t nat -C POSTROUTING -s 10.8.0.0/24 -o ens3 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o ens3 -j MASQUERADE
iptables -C FORWARD -i wg0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i wg0 -j ACCEPT
iptables -C FORWARD -o wg0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -o wg0 -j ACCEPT

# Ждём tun0 от sing-box (до 30 секунд)
for i in $(seq 1 30); do
    ip link show tun0 >/dev/null 2>&1 && break
    sleep 1
done

ip route replace default dev tun0 table middleman
ip route replace 10.8.0.0/24 dev wg0 table middleman
ip rule del fwmark 0x64 2>/dev/null || true
ip rule add fwmark 0x64 lookup middleman priority 100
ip route replace 203.0.113.10/32 via 198.51.100.1 dev ens3
sysctl -q net.ipv4.ip_forward=1
echo "[$(date)] vpn-boot-setup completed"
