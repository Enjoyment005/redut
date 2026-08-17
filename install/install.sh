#!/bin/bash
# install.sh — ИДЕМПОТЕНТНЫЙ серверный установщик базы VPN-узла (схема node1).
#
# Ставит с голого Debian 13 всё, КРОМЕ веб-панели/агента (их накатывает bootstrap.py
# через panel/deploy.py): пакеты, sing-box 1.11.7 (бинарь с GitHub), WireGuard
# (сервер+клиенты), sing-box config, self-heal, vpn-boot-setup (с §11 RETURN и
# фолбэком подъёма wg0), microsocks, iptables/маршруты, кроны.
#
# Параметры читает из params.sh (генерит bootstrap.py). Можно и вручную на сервере:
#     cd /opt/vpn-install && bash install.sh
#
# Идемпотентно: повторный запуск не дублирует правила и не теряет ключи/клиентов.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PARAMS="${PARAMS:-$HERE/params.sh}"
TPL="$HERE/templates"
# Клиентские .conf храним в каноничном месте — их читает/пишет и веб-панель (управление
# конфигами: список/создать/удалить/QR). bootstrap забирает их отсюда.
CLIENTS_OUT="/etc/wireguard/clients"

[ -f "$PARAMS" ] || { echo "[install][FATAL] нет $PARAMS" >&2; exit 1; }
[ -d "$TPL" ]    || { echo "[install][FATAL] нет каталога templates ($TPL)" >&2; exit 1; }

# Экспортируем все параметры (нужны и дочернему python3 при сборке sing-box config).
set -a
# shellcheck disable=SC1090
. "$PARAMS"
set +a

log(){ echo "[install] $*"; }
die(){ echo "[install][FATAL] $*" >&2; exit 1; }

# Копия текстового шаблона со снятием CR (репозиторий на Windows может быть в CRLF).
put_tpl(){ # src dst mode
    sed 's/\r$//' "$1" > "$2" || die "не скопировать $1 -> $2"
    chmod "$3" "$2"
}

# ─────────────────────────────────────────────────────────────────────────
log "узел '$NAME' ($ROLE): subnet $SUBNET, wan $WAN, gw $GW, ip $SERVER_IP, upstream $UP_HOST"

# ── 1. Пакеты + ip_forward (persist) ─────────────────────────────────────
log "1/12 apt пакеты"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y            || die "apt-get update"
apt-get install -y wireguard wireguard-tools ipset iptables curl wget tar \
        python3 dnsmasq microsocks chrony ca-certificates || die "apt-get install"
echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-vpn.conf
sysctl -q -p /etc/sysctl.d/99-vpn.conf 2>/dev/null || sysctl -q net.ipv4.ip_forward=1 || true

# ── 2. sing-box (статический бинарь с GitHub, пин версии) ─────────────────
log "2/12 sing-box $SINGBOX_VERSION"
cur=""
[ -x /usr/local/bin/sing-box ] && cur="$(/usr/local/bin/sing-box version 2>/dev/null | awk '/version/{print $NF; exit}')"
if [ "$cur" != "$SINGBOX_VERSION" ]; then
    tmp="$(mktemp -d)"; arch="linux-amd64"
    url="https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-${arch}.tar.gz"
    log "  качаю $url"
    curl -fsSL "$url" -o "$tmp/sb.tgz" || wget -qO "$tmp/sb.tgz" "$url" || { rm -rf "$tmp"; die "не скачался sing-box"; }
    tar -xzf "$tmp/sb.tgz" -C "$tmp" || { rm -rf "$tmp"; die "не распаковался sing-box"; }
    install -m 0755 "$tmp/sing-box-${SINGBOX_VERSION}-${arch}/sing-box" /usr/local/bin/sing-box || { rm -rf "$tmp"; die "install sing-box"; }
    rm -rf "$tmp"
fi
got="$(/usr/local/bin/sing-box version 2>/dev/null | awk '/version/{print $NF; exit}')"
[ "$got" = "$SINGBOX_VERSION" ] || die "sing-box версия '$got' != '$SINGBOX_VERSION'"
log "  sing-box $got OK"

# ── 3. таблица middleman (id 200) — /etc/iproute2/rt_tables может отсутствовать ──
log "3/12 rt_tables 200 middleman"
mkdir -p /etc/iproute2/rt_tables.d
if ! grep -rhqw middleman /etc/iproute2/rt_tables /etc/iproute2/rt_tables.d 2>/dev/null; then
    echo '200 middleman' > /etc/iproute2/rt_tables.d/middleman.conf
fi

# ── 4. WireGuard: ключи сервера + клиентов, wg0.conf, клиентские .conf ────
log "4/12 WireGuard (ключи + wg0.conf + клиенты)"
mkdir -p /etc/wireguard "$CLIENTS_OUT"
chmod 700 "$CLIENTS_OUT"
( cd /etc/wireguard && umask 077
  [ -f server_private.key ] || { wg genkey | tee server_private.key | wg pubkey > server_public.key; }
  for pair in $CLIENTS; do
      cname="${pair%%:*}"
      [ -f "${cname}_private.key" ] || { wg genkey | tee "${cname}_private.key" | wg pubkey > "${cname}_public.key"; }
      [ -f "${cname}_psk.key" ]     || wg genpsk > "${cname}_psk.key"
  done )
SERVER_PRIV="$(cat /etc/wireguard/server_private.key)"
SERVER_PUB="$(cat /etc/wireguard/server_public.key)"

# wg0.conf: БЕЗ iptables в PostUp — masquerade/forward живут ТОЛЬКО в vpn-boot-setup.sh
# (единое место, идемпотентно; §5: на старом node1 дублировались boot-скрипт + PostUp).
#
# ВАЖНО (исправлено 2026-08-15): раньше файл собирался с нуля по списку CLIENTS,
# и повторный запуск установщика ВЫБРАСЫВАЛ устройства, заведённые позже через
# веб-панель — человек «обновлял узел» и молча терял доступ у половины семьи.
# Теперь чужие [Peer] сохраняются: пишем клиентов из CLIENTS и дописываем всех
# остальных пиров, найденных в текущем конфиге.
{
  echo "[Interface]"
  echo "Address = $WG_ADDR"
  echo "ListenPort = $WG_PORT"
  echo "PrivateKey = $SERVER_PRIV"
  echo "# iptables/маршруты — в /usr/local/bin/vpn-boot-setup.sh (единое место, идемпотентно)."
  echo "PostUp = sysctl -w net.ipv4.ip_forward=1"
  known_pubs=""
  for pair in $CLIENTS; do
      cname="${pair%%:*}"; caddr="${pair##*:}"
      cpub="$(cat /etc/wireguard/${cname}_public.key)"
      cpsk="$(cat /etc/wireguard/${cname}_psk.key)"
      known_pubs="$known_pubs $cpub"
      echo ""
      echo "[Peer]"
      echo "# $cname"
      echo "PublicKey = $cpub"
      echo "PresharedKey = $cpsk"
      echo "AllowedIPs = ${caddr}/32"
  done
  if [ -f /etc/wireguard/wg0.conf ]; then
      KNOWN_PUBS="$known_pubs" python3 - /etc/wireguard/wg0.conf <<'PY'
import os, re, sys
known = set((os.environ.get("KNOWN_PUBS") or "").split())
text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
for block in re.split(r"(?m)^\[Peer\]\s*$", text)[1:]:
    block = block.split("[Interface]")[0].rstrip()
    m = re.search(r"(?m)^\s*PublicKey\s*=\s*(\S+)", block)
    if not m or m.group(1) in known:
        continue          # этот клиент уже описан выше — не задваиваем
    sys.stdout.write("\n[Peer]" + block.rstrip() + "\n")
PY
  fi
} > /etc/wireguard/wg0.conf.new
mv /etc/wireguard/wg0.conf.new /etc/wireguard/wg0.conf
chmod 600 /etc/wireguard/wg0.conf

# Клиентские .conf (в /opt/vpn-install/clients/, bootstrap их заберёт)
for pair in $CLIENTS; do
    cname="${pair%%:*}"; caddr="${pair##*:}"
    cpriv="$(cat /etc/wireguard/${cname}_private.key)"
    cpsk="$(cat /etc/wireguard/${cname}_psk.key)"
    cat > "$CLIENTS_OUT/${cname}.conf" <<CCONF
[Interface]
PrivateKey = $cpriv
Address = ${caddr}/32
DNS = $DNS_SERVER

[Peer]
PublicKey = $SERVER_PUB
PresharedKey = $cpsk
Endpoint = ${SERVER_IP}:${WG_PORT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
CCONF
    chmod 600 "$CLIENTS_OUT/${cname}.conf"
done

# Надёжный автозапуск на буте (баг node1: wg-quick@wg0 enabled, но не встал):
# 1) ordering после network-online; 2) фолбэк-подъём в vpn-boot-setup.sh (§7).
mkdir -p /etc/systemd/system/wg-quick@wg0.service.d
cat > /etc/systemd/system/wg-quick@wg0.service.d/override.conf <<'EOF'
[Unit]
After=network-online.target
Wants=network-online.target
EOF

# ── 5. sing-box config из шаблона с подстановкой upstream ────────────────
log "5/12 sing-box config"
mkdir -p /etc/sing-box
python3 - "$TPL/sing-box.config.json" /etc/sing-box/config.json <<'PY' || die "сборка sing-box config"
import json, os, sys
src, dst = sys.argv[1], sys.argv[2]
with open(src, encoding="utf-8") as f:
    c = json.load(f)
host = os.environ["UP_HOST"]; user = os.environ["UP_USER"]; pw = os.environ["UP_PASS"]
socks = int(os.environ["UP_SOCKS"] or 0); http = int(os.environ["UP_HTTP"] or 0)

# ИСПРАВЛЕНО 2026-08-15: сохраняем ЖИВОЙ исходящий канал при повторной установке.
# Раньше конфиг всегда пересобирался по params.sh, и переустановка откатывала канал,
# выбранный панелью/автоматикой, на дефолт из профиля: узел «обновили» — и выход
# внезапно поехал через старый адрес. Явно заданный канал (UP_FORCE=1) имеет приоритет.
#
# УТОЧНЕНО 15.08 (снос №4): переносим ЖИВЫЕ outbounds и route ЦЕЛИКОМ, а не только адрес/порты.
# Раньше типы outbound'ов брались из шаблона (socks-out=socks, http-tg=http), а порты — из
# живого конфига. Если агент перевёл канал в HTTP-режим (RETUNE §7.3: оба outbound'а http +
# правило reject UDP443), переустановка ставила тип socks на http-порт — канал ломался
# ровно на «обновлении». Теперь секции, которыми владеет агент (outbounds, route), не
# пересобираются: из шаблона идут только inbounds/dns/log; результат проверяет sing-box check.
kept = False
if os.environ.get("UP_FORCE") != "1" and os.path.isfile(dst):
    try:
        with open(dst, encoding="utf-8") as f:
            live = json.load(f)
        cur = {o.get("tag"): o for o in live.get("outbounds", [])}
        so = cur.get("socks-out") or {}
        if so.get("server") and isinstance(live.get("route"), dict):
            c["outbounds"] = live["outbounds"]
            c["route"] = live["route"]
            kept = True
            print("[install]   сохраняю текущий исходящий канал %s (переустановка его не меняет; "
                  "outbounds/route — из живого конфига)" % so["server"])
    except (ValueError, OSError, TypeError):
        pass          # битый конфиг — соберём заново из параметров

if not kept:
    for o in c.get("outbounds", []):
        if o.get("tag") == "socks-out":
            o.update(server=host, server_port=socks, username=user, password=pw)
        elif o.get("tag") == "http-tg":
            o.update(server=host, server_port=http, username=user, password=pw)
with open(dst, "w", encoding="utf-8") as f:
    json.dump(c, f, ensure_ascii=False, indent=2)
PY
/usr/local/bin/sing-box check -c /etc/sing-box/config.json || die "sing-box check не прошёл"
# Действующий upstream (сохранённый живой или из params.sh; в публичной сборке при первой
# установке — ПУСТО: канал появится после мастера). Именно он идёт в boot-скрипт и verify.
UP_HOST_EFF="$(python3 -c 'import json,sys
c = json.load(open(sys.argv[1], encoding="utf-8"))
print(next((o.get("server") or "" for o in c.get("outbounds", []) if o.get("tag") == "socks-out"), ""))' \
    /etc/sing-box/config.json 2>/dev/null || true)"

# ── 6. self-heal (unit + post + watchdog) из templates/ ──────────────────
log "6/12 self-heal (sing-box.service, singbox-post, watchdog)"
put_tpl "$TPL/sing-box.service"     /etc/systemd/system/sing-box.service      0644
put_tpl "$TPL/singbox-post.sh"      /usr/local/bin/singbox-post.sh            0755
put_tpl "$TPL/singbox-watchdog.sh"  /usr/local/bin/singbox-watchdog.sh        0755
put_tpl "$TPL/vpn-boot-setup.service" /etc/systemd/system/vpn-boot-setup.service 0644

# Гигиена следов: журналы (IP клиентов и dst), история логинов/команд, apt/dpkg.
# Скрипт ставим всегда; крон (0 */3) навешиваем в §11 при CLEANUP=1 (по умолчанию вкл).
put_tpl "$TPL/server_cleanup.sh"    /usr/local/bin/server_cleanup.sh          0755

# ── 7. vpn-boot-setup.sh — с §11 RETURN и фолбэком wg0 (переживает ребут) ─
log "7/12 vpn-boot-setup.sh (§11 RETURN + wg0 fallback)"
cat > /usr/local/bin/vpn-boot-setup.sh <<BOOT
#!/bin/bash
# VPN boot setup — subnet $SUBNET, upstream $UP_HOST_EFF (сгенерирован install.sh).
# Идемпотентно, переживает ребут. §11: RETURN для трафика ВНУТРИ VPN и К самому серверу
# (панель/SSH из-под VPN не заворачиваются в middleman->tun0). Плюс фолбэк подъёма wg0.
# UP_HOST правит агент (apply.patch_boot_script) при смене канала; пусто = канал ещё не выбран.
UP_HOST="$UP_HOST_EFF"

# 0) фолбэк — поднять wg0, если systemd не поднял его на буте (случалось на живом узле)
if ! ip link show wg0 >/dev/null 2>&1; then
    systemctl start wg-quick@wg0 2>/dev/null || wg-quick up wg0 2>/dev/null || true
fi

ipset create ru_whitelist hash:ip timeout 7200 2>/dev/null || true
# Статический белый список сетей РФ (IP/CIDR из GitHub). Файл пишет update-ru-whitelist.sh;
# на ребуте восстанавливаем набор из него, без обращения к сети. Нет файла (напр. dnsmasq
# выключен) -> блок пропускается, правило ниже не навешивается.
if [ -f /etc/ru_whitelist_net.ipset ]; then
    ipset create ru_whitelist_net hash:net family inet hashsize 16384 maxelem 1000000 2>/dev/null || true
    ipset flush ru_whitelist_net 2>/dev/null || true
    grep '^add ' /etc/ru_whitelist_net.ipset | sed 's/^add [^ ]* /add ru_whitelist_net /' | ipset restore -! 2>/dev/null || true
fi

# mangle PREROUTING: whitelist(домены+сети) RETURN -> §11 RETURN (внутри VPN + сам сервер) -> MARK 0x64
iptables -t mangle -F PREROUTING
iptables -t mangle -A PREROUTING -s $SUBNET -m set --match-set ru_whitelist dst -j RETURN
if ipset list -n ru_whitelist_net >/dev/null 2>&1; then
    iptables -t mangle -A PREROUTING -s $SUBNET -m set --match-set ru_whitelist_net dst -j RETURN
fi
iptables -t mangle -A PREROUTING -s $SUBNET -d $SUBNET -j RETURN
iptables -t mangle -A PREROUTING -s $SUBNET -d $SERVER_IP/32 -j RETURN
iptables -t mangle -A PREROUTING -s $SUBNET -j MARK --set-mark 0x64

# nat/forward — ЕДИНСТВЕННОЕ место (в wg0.conf их нет), идемпотентно (-C || -A)
iptables -t nat -C POSTROUTING -s $SUBNET -o $WAN -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s $SUBNET -o $WAN -j MASQUERADE
iptables -C FORWARD -i wg0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i wg0 -j ACCEPT
iptables -C FORWARD -o wg0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -o wg0 -j ACCEPT

# ждём tun0 от sing-box (до 30 с)
for i in \$(seq 1 30); do ip link show tun0 >/dev/null 2>&1 && break; sleep 1; done

if [ -n "\$UP_HOST" ]; then
    # канал выбран: клиенты -> tun0 -> sing-box -> upstream
    ip route replace default dev tun0 table middleman
    # анти-луп: до самого upstream — напрямую через WAN
    ip route replace "\$UP_HOST/32" via $GW dev $WAN
else
    # Канал ещё не выбран (публичная сборка до мастера): в tun0 отправлять некуда, и
    # раньше после каждой перезагрузки клиенты сидели без сети до первого тика сторожа
    # (измерено 143 с, снос №4 15.08). Сразу прямой выход адресом сервера + флаг аварийного
    # режима: сторож при флаге маршрут не «чинит» обратно в мёртвый tun0, агент видит
    # флаг и не-tun0 — восстанавливать нечего, а из аварии выйдет сам, когда появится канал.
    ip route replace default via $GW dev $WAN table middleman
    echo "\$(date '+%F %T') boot: канал не выбран — прямой выход" > /run/vpn-agent-emergency
fi
ip route replace $SUBNET dev wg0 table middleman
ip rule del fwmark 0x64 2>/dev/null || true
ip rule add fwmark 0x64 lookup middleman priority 100
sysctl -q net.ipv4.ip_forward=1
echo "[\$(date)] vpn-boot-setup completed (upstream: \${UP_HOST:-не выбран, прямой выход})"
BOOT
chmod 755 /usr/local/bin/vpn-boot-setup.sh

# ── 8. microsocks (SOCKS5 для приложений, :1080) ─────────────────────────
# ИСПРАВЛЕНО 2026-08-15 (снос №4, приёмка публичной сборки): пароль профиля в публичной
# сборке — заглушка CHANGE_ME_SOCKS_PASS, и она уходила прямо в юнит. Каждый узел,
# поставленный одной командой, слушал 0.0.0.0:1080 с паролем, опубликованным на GitHub, —
# открытый SOCKS5 для всего интернета с выходом адресом сервера (проверено снаружи на node1:
# curl --socks5-hostname <ip>:1080 --proxy-user proxyuser:CHANGE_ME_SOCKS_PASS -> IP сервера).
# Теперь: заглушка/пусто -> случайный пароль, который переживает повторные установки
# (/etc/microsocks.env, 0600); юнит читает креды из этого файла (EnvironmentFile), а не из
# командной строки установщика. Явный пароль профиля (частная сборка) по-прежнему главнее.
log "8/12 microsocks :$MICROSOCKS_PORT"
MS_ENV="${MS_ENV:-/etc/microsocks.env}"     # переопределяем только в локальном тесте логики
MS_USER="${MICROSOCKS_USER:-proxyuser}"
MS_PASS="${MICROSOCKS_PASS:-}"
ms_is_placeholder(){ case "$1" in ""|*CHANGE_ME*|*change_me*|*CHANGEME*) return 0;; *) return 1;; esac; }
if ms_is_placeholder "$MS_PASS"; then
    # берём уже сгенерированный (повторный прогон), иначе генерим новый
    if [ -f "$MS_ENV" ]; then
        MS_PASS="$(sed -n 's/^MICROSOCKS_PASS=//p' "$MS_ENV" | head -1 | sed 's/^"//; s/"$//')"
        # сохраняем пароль из env -> сохраняем и логин-пару к нему: иначе профильный
        # логин при чужом/кастомном env отвалил бы приложения со старыми кредами
        ms_env_user="$(sed -n 's/^MICROSOCKS_USER=//p' "$MS_ENV" | head -1 | sed 's/^"//; s/"$//')"
        [ -n "$ms_env_user" ] && MS_USER="$ms_env_user"
    fi
    if ms_is_placeholder "$MS_PASS"; then
        MS_PASS="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24)"
        [ ${#MS_PASS} -ge 20 ] || die "не сгенерировать пароль SOCKS5 (/dev/urandom?)"
        log "  пароль SOCKS5 сгенерирован (заглушка профиля не используется) -> $MS_ENV"
    else
        log "  пароль SOCKS5 сохранён из $MS_ENV (повторная установка его не меняет)"
    fi
fi
( umask 077; printf 'MICROSOCKS_USER="%s"\nMICROSOCKS_PASS="%s"\n' "$MS_USER" "$MS_PASS" > "$MS_ENV.new" ) \
    && mv "$MS_ENV.new" "$MS_ENV" && chmod 600 "$MS_ENV" || die "не записать $MS_ENV"
cat > /etc/systemd/system/microsocks.service <<EOF
[Unit]
Description=MicroSOCKS SOCKS5 Proxy
After=network.target wg-quick@wg0.service

[Service]
Type=simple
# логин/пароль — в $MS_ENV (0600); заглушка из репозитория сюда не попадает (install.sh §8)
EnvironmentFile=$MS_ENV
ExecStart=/usr/bin/microsocks -i 0.0.0.0 -p $MICROSOCKS_PORT -u \${MICROSOCKS_USER} -P \${MICROSOCKS_PASS}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# ── 9. dnsmasq (по умолчанию ВЫКЛ; включаем только если DNSMASQ=1) ────────
if [ "$DNSMASQ" = "1" ]; then
    log "9/12 dnsmasq ON ($WG_IP:53 + ru_whitelist)"
    systemctl disable --now systemd-resolved 2>/dev/null || true
    # bind-dynamic, НЕ bind-interfaces: dnsmasq слушает адрес wg0 ($WG_IP), который на буте
    # появляется ПОЗЖЕ старта dnsmasq. С bind-interfaces демон падал бы «failed to create
    # listening socket ... Cannot assign requested address» (найдено на приёмке node2 2026-08-17,
    # ребут). bind-dynamic привязывается к адресу, когда интерфейс поднялся, и переживает ребут.
    cat > /etc/dnsmasq.d/vpn-main.conf <<EOF
listen-address=$WG_IP,127.0.0.1
bind-dynamic
port=53
no-resolv
server=1.1.1.1
server=8.8.8.8
cache-size=1000
EOF
    put_tpl "$TPL/dnsmasq/no-log.conf" /etc/dnsmasq.d/no-log.conf 0644
    # Белый список РФ-доменов (прямой выход через РФ-адрес): сид сразу (~447 доменов),
    # плюс апдейтер + git для него. Без сида ipset ru_whitelist наполнялся бы с нуля.
    put_tpl "$TPL/dnsmasq/ru-whitelist.conf" /etc/dnsmasq.d/ru-whitelist.conf   0644
    put_tpl "$TPL/update-ru-whitelist.sh"    /usr/local/bin/update-ru-whitelist.sh 0755
    command -v git >/dev/null 2>&1 || apt-get install -y -qq git >/dev/null 2>&1 || true
else
    log "9/12 dnsmasq OFF (весь трафик клиентов уходит в исходящий канал; DNS клиента $DNS_SERVER)"
    systemctl disable --now dnsmasq 2>/dev/null || true
fi

# ── 10. Поднять базу (порядок: wg0 -> sing-box(tun0) -> boot-setup(маршруты)) ──
log "10/12 запуск базовых сервисов"
systemctl daemon-reload
systemctl enable wg-quick@wg0 sing-box vpn-boot-setup microsocks >/dev/null 2>&1 || true

# wg0: идемпотентно (без разрыва интерфейса при повторном прогоне с живым клиентом)
if systemctl is-active --quiet wg-quick@wg0; then
    wg syncconf wg0 <(wg-quick strip wg0) 2>/dev/null || systemctl restart wg-quick@wg0
else
    systemctl start wg-quick@wg0 || die "wg-quick@wg0 не поднялся"
fi
systemctl restart microsocks || true
systemctl restart sing-box; sleep 3
bash /usr/local/bin/vpn-boot-setup.sh || true
systemctl start vpn-boot-setup 2>/dev/null || true   # RemainAfterExit=yes -> отметится active
if [ "$DNSMASQ" = "1" ]; then
    ipset create ru_whitelist hash:ip timeout 7200 2>/dev/null || true
    systemctl enable --now dnsmasq 2>/dev/null || true
    # Первое наполнение белого списка из GitHub (сид уже применён — это лишь освежает).
    # Не критично: нет сети к GitHub/нет git -> остаёмся на сиде, крон обновит в воскресенье.
    /usr/local/bin/update-ru-whitelist.sh >/dev/null 2>&1 || true
fi

# ── 11. Кроны узла (агентские кроны добавит deploy.py/setup_panel) ────────
# Сторож — всегда. Чистка следов — при CLEANUP=1 (по умолчанию вкл; CLEANUP=0 для
# тест-стенда, чтобы не тереть journald между тестами). Белый список — только при
# dnsmasq (иначе ipset ru_whitelist негде наполнять). Идемпотентно: свои строки
# срезаем и добавляем заново. Агентские (pool-refresh/heartbeat) не трогаем.
CLEANUP="${CLEANUP:-1}"
log "11/12 cron (watchdog */2; cleanup 0 */3 = $CLEANUP; whitelist 0 3 * * 0 при dnsmasq=$DNSMASQ)"
{
    crontab -l 2>/dev/null | grep -v 'singbox-watchdog' | grep -v 'server_cleanup' | grep -v 'update-ru-whitelist'
    echo '*/2 * * * * /usr/local/bin/singbox-watchdog.sh'
    [ "$CLEANUP" = "1" ] && echo '0 */3 * * * /usr/local/bin/server_cleanup.sh'
    [ "$DNSMASQ" = "1" ] && echo '0 3 * * 0 /usr/local/bin/update-ru-whitelist.sh >> /var/log/ru-whitelist-update.log 2>&1'
    true
} | crontab -

# ── 12. Verify базы ──────────────────────────────────────────────────────
log "12/12 verify"
echo "  sing-box: $(/usr/local/bin/sing-box version 2>/dev/null | awk '/version/{print $NF; exit}')"
for s in wg-quick@wg0 sing-box microsocks vpn-boot-setup; do
    echo "  $s: $(systemctl is-active $s 2>/dev/null)"
done
echo "  tun0 carrier: $(cat /sys/class/net/tun0/carrier 2>/dev/null || echo none)"
echo "  wg peers: $(wg show wg0 peers 2>/dev/null | wc -l)"
echo "  middleman: $(ip route show table middleman 2>/dev/null | tr '\n' ';')"
echo "  mangle §11 RETURN: $(iptables -t mangle -S PREROUTING 2>/dev/null | grep -c -- '-j RETURN')"
# SOCKS5 :1080 слушает весь интернет — пароль-заглушка из репозитория недопустим (снос №4)
if grep -qi 'CHANGE_ME' /etc/microsocks.env /etc/systemd/system/microsocks.service 2>/dev/null; then
    echo "  microsocks: ОШИБКА — в кредах SOCKS5 осталась заглушка CHANGE_ME (см. §8)"
else
    echo "  microsocks: креды свои (не заглушка), файл /etc/microsocks.env $(stat -c %a /etc/microsocks.env 2>/dev/null)"
fi
if [ -n "$UP_HOST_EFF" ]; then
    egress="$(curl -s --max-time 15 --interface tun0 https://api.ipify.org 2>/dev/null || true)"
    echo "  egress(tun0): ${egress:-ПУСТО}  (ждём upstream $UP_HOST_EFF)"
else
    echo "  egress(tun0): канал ещё не выбран — появится после ввода ключа провайдера в мастере"
fi
echo "  cron: watchdog=$(crontab -l 2>/dev/null | grep -c 'singbox-watchdog') cleanup=$(crontab -l 2>/dev/null | grep -c 'server_cleanup') whitelist=$(crontab -l 2>/dev/null | grep -c 'update-ru-whitelist')"
if [ "$DNSMASQ" = "1" ]; then
    echo "  ru_whitelist: доменов в конфиге $(grep -c '^ipset=/' /etc/dnsmasq.d/ru-whitelist.conf 2>/dev/null || echo 0), dnsmasq $(systemctl is-active dnsmasq 2>/dev/null)"
    echo "  ru_whitelist_net: $(ipset list ru_whitelist_net 2>/dev/null | sed -n 's/^Number of entries: //p' | head -1 || echo 0) сетей РФ (IP/CIDR)"
fi
log "база готова. Дальше — агент и веб-панель (setup.sh / bootstrap.py ставят их следующим шагом)."
