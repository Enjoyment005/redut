#!/bin/bash
# setup.sh — установка узла «Редут» ОДНОЙ КОМАНДОЙ прямо на сервере.
#
#   bash <(curl -fsSL https://raw.githubusercontent.com/Enjoyment005/redut/main/setup.sh \
#          || wget -qO- https://raw.githubusercontent.com/Enjoyment005/redut/main/setup.sh)
#
# Скрипт рассчитан на чистую Debian 13 и запуск от root. Он скачивает репозиторий,
# ставит базу (WireGuard, sing-box, маршруты, самолечение) и веб-панель, после чего
# печатает адрес мастера первого входа.
#
# Почему `bash <(curl …)`, а не `curl … | bash`: при пайпе у скрипта нет stdin, и он
# не может ничего спросить у человека. Здесь stdin остаётся терминалом.
# Почему `curl … || wget …`: на минимальных образах Debian 13 (netinst у российских
# хостеров) curl не установлен, а wget есть; с одним curl команда молча делала ничего
# (bash получал пустой файл и выходил с кодом 0). Проверено на живом сервере 15.08.
#
# Идемпотентно: повторный запуск обновляет узел, не теряя ключи, клиентов и учётку панели.
#
# Переменные окружения (все необязательные):
#   REPO=владелец/имя    другой репозиторий (по умолчанию — официальный, см. ниже)
#   BRANCH=main          ветка
#   NAME=node1           имя узла
#   PANEL_PORT=8443      порт веб-панели
#   SUBNET=10.8.0.0/24   клиентская подсеть
#   CLIENTS=phone1       клиенты через запятую (или число: client1..N)
#   PROFILE=<имя>        базовый профиль из install/profiles.py (по умолчанию — профиль
#                        с именем узла, если есть, иначе первый по алфавиту)
#   CLEANUP=1            чистка следов кроном 0 */3 (0 = выключить, напр. на тест-стенде)
#   UPDATE=1             режим ОБНОВЛЕНИЯ уже установленного узла: имя/подсеть/порты
#                        читаются из живого /etc/vpn-panel/config.json (NAME/SUBNET/
#                        CLIENTS игнорируются), клиенты не добавляются, решение о
#                        чистке следов — по текущему крону. Этим путём ходит и
#                        самообновление (vpn-agent self-update, план vpn/UPDATE-PLAN.md)
set -euo pipefail

# Полный PATH: при запуске из крона (самообновление) PATH урезан до /usr/bin:/bin,
# и iptables/ipset/sysctl из sbin молча «не находились» бы (ревью 17.08).
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Явность переменных запоминаем ДО дефолтов — по ней ниже включается режим
# обновления, когда узел уже установлен, а параметров человек не передал.
_NAME_SET="${NAME+x}"; _SUBNET_SET="${SUBNET+x}"; _CLIENTS_SET="${CLIENTS+x}"; _UPDATE_SET="${UPDATE+x}"

REPO="${REPO:-Enjoyment005/redut}"
BRANCH="${BRANCH:-main}"
NAME="${NAME:-node1}"
PANEL_PORT="${PANEL_PORT:-8443}"
SUBNET="${SUBNET:-10.8.0.0/24}"
CLIENTS="${CLIENTS:-phone1}"
WORKDIR="/opt/redut-src"

say()  { printf '\n\033[1;36m▸ %s\033[0m\n' "$*"; }
ok()   { printf '  \033[1;32m✔\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31m✖ %s\033[0m\n' "$*" >&2; exit 1; }

# ── 0a. UPDATE=1 — обновление УЖЕ установленного узла ────────────────────────
# Повторный прогон установки корректно обновляет узел только при ТОЧНОМ повторе
# переменных первой установки: дефолтный NAME=node1 переименовал бы узел (а роль —
# это привязка прокси в пуле, та же грабля, что у deploy.py до --keep-config),
# CLIENTS=phone1 дописал бы лишнего клиента. Поэтому в режиме обновления параметры
# читаются из живого /etc/vpn-panel/config.json, клиенты не добавляются вовсе
# (существующих сохраняет install.sh §4), а выбор владельца по чистке следов
# не переигрывается (смотрим текущий крон). Секреты, канал, cert не трогаются —
# это гарантии идемпотентного инсталлятора, режим их только не портит параметрами.
# Узел уже установлен, а параметры установки не заданы? Голый повторный прогон
# переустановил бы его ДЕФОЛТАМИ (NAME=node1, SUBNET=10.8.0.0/24, CLIENTS=phone1) —
# включаем режим обновления сами (ревью 17.08). Отключить: явно UPDATE=0.
if [ -z "$_UPDATE_SET" ] && [ -f /etc/vpn-panel/config.json ] \
   && [ -z "$_NAME_SET$_SUBNET_SET$_CLIENTS_SET" ]; then
    UPDATE=1
    printf '  \033[1;33m!\033[0m узел уже установлен, а NAME/SUBNET/CLIENTS не заданы — включаю режим обновления (UPDATE=1)\n'
fi
UPDATE="${UPDATE:-0}"
export UPDATE                       # решение видят и python-хередоки (§3: секреты профиля)
OLD_VER=""
if [ "$UPDATE" = "1" ]; then
    CFG_LIVE=/etc/vpn-panel/config.json
    [ -f "$CFG_LIVE" ] || die "UPDATE=1, а $CFG_LIVE нет — узел не установлен (запусти без UPDATE)"
    command -v python3 >/dev/null || die "UPDATE=1: нужен python3 (на установленном узле он есть)"
    upd_vars="$(python3 - "$CFG_LIVE" <<'PY'
import json, shlex, sys
try:
    with open(sys.argv[1], encoding="utf-8") as f:
        c = json.load(f)
except (ValueError, OSError) as e:
    sys.exit("config.json не прочитать/не разобрать как JSON: %s" % e)
def need(key):
    v = c.get(key)
    if v in (None, ""):
        sys.exit("в config.json нет «%s» — не зная параметров узла, обновляться нельзя" % key)
    return v
try:
    panel_port = int(c.get("panel_port") or 8443)
except (TypeError, ValueError):
    sys.exit("panel_port в config.json не число: %r" % (c.get("panel_port"),))
print("NAME=%s" % shlex.quote(str(need("server"))))
print("SUBNET=%s" % shlex.quote(str(need("subnet"))))
print("PANEL_PORT=%d" % panel_port)
print("UPD_WG_PORT=%s" % shlex.quote(str(c.get("wg_port") or "")))
print("UPD_DNSMASQ=%s" % ("1" if c.get("has_dnsmasq") else "0"))
PY
)" || die "не разобрать $CFG_LIVE"
    eval "$upd_vars"
    # Порт wg: ЖИВОЙ узел главнее записи — исторически setup.sh не передавал порт
    # панели, и config.json мог хранить дефолт 51820 при другом фактическом порте;
    # смена порта на обновлении отвалила бы всех клиентов (Endpoint=IP:старый).
    wgp_live="$(sed -n 's/^ListenPort *= *//p' /etc/wireguard/wg0.conf 2>/dev/null | head -1 | tr -d ' \r')"
    case "$wgp_live" in
        ""|*[!0-9]*) : ;;
        *) UPD_WG_PORT="$wgp_live" ;;
    esac
    export UPD_WG_PORT UPD_DNSMASQ
    CLIENTS=""                      # никого не добавлять; §4 install.sh сохранит существующих
    OLD_VER="$(cat /opt/vpn-panel/VERSION 2>/dev/null || true)"
    if [ -z "${CLEANUP:-}" ]; then  # выбор владельца по чистке следов не переигрываем
        # ^[^#] — закомментированная строка чистки не считается включённой
        if crontab -l 2>/dev/null | grep -q '^[^#].*server_cleanup\.sh'; then CLEANUP=1; else CLEANUP=0; fi
    fi
    export CLEANUP
    say "Режим обновления: узел «$NAME» (сеть $SUBNET, панель :$PANEL_PORT, wg-порт ${UPD_WG_PORT:-по профилю}, dnsmasq=$UPD_DNSMASQ, чистка=$CLEANUP, сейчас Редут ${OLD_VER:-?})"
fi

# ── 0. Проверки окружения ───────────────────────────────────────────────────
say "Проверяю сервер"
[ "$(id -u)" = "0" ] || die "нужен root: запусти через sudo -i или от root"
[ -r /etc/os-release ] || die "не похоже на Linux с /etc/os-release"
# os-release читаем в подоболочке: он объявляет свою переменную NAME («Debian GNU/Linux»)
# и иначе затирает имя узла — так узел получал имя 'Debian GNU/Linux' (найдено 15.08).
OS_ID="$(. /etc/os-release && printf '%s' "${ID:-}")"
OS_VER="$(. /etc/os-release && printf '%s' "${VERSION_ID:-}")"
OS_PRETTY="$(. /etc/os-release && printf '%s' "${PRETTY_NAME:-неизвестно}")"
[ "$OS_ID" = "debian" ] || die "нужен Debian (у тебя: $OS_PRETTY). Установщик проверялся на Debian 13."
case "$OS_VER" in
    13*) ok "Debian $OS_VER — то, что нужно" ;;
    *)   printf '  \033[1;33m!\033[0m Debian %s вместо 13 — не проверялось, продолжаю на свой страх\n' "${OS_VER:-?}" ;;
esac
case "$NAME" in
    ""|*[!A-Za-z0-9._-]*) die "NAME='$NAME' — имя узла: латиница, цифры, точка, дефис, подчёркивание" ;;
esac
[ "$(uname -m)" = "x86_64" ] || die "нужна архитектура x86_64 (у тебя $(uname -m))"
command -v systemctl >/dev/null || die "нет systemd"
ip route show default | grep -q . || die "нет маршрута по умолчанию — сервер без сети?"
ok "root, systemd, сеть на месте"

# ── 1. Минимальные зависимости для самой установки ──────────────────────────
say "Ставлю curl/tar/python3 (если их нет)"
export DEBIAN_FRONTEND=noninteractive
missing=""
for p in curl tar python3; do command -v "$p" >/dev/null || missing="$missing $p"; done
if [ -n "$missing" ]; then
    apt-get update -qq >/dev/null 2>&1 || true
    # shellcheck disable=SC2086
    apt-get install -y -qq $missing >/dev/null || die "не поставить:$missing"
fi
ok "curl, tar, python3 готовы"

# ── 2. Исходники ────────────────────────────────────────────────────────────
# SRC_DIR — уже распакованный репозиторий (склонировали руками / копия на диске).
# Тогда ничего не качаем: удобно без интернета к GitHub и при доработке скрипта.
SRC_DIR="${SRC_DIR:-}"
if [ -z "$SRC_DIR" ] && [ -f "$(dirname "$0")/install/install.sh" ]; then
    SRC_DIR="$(cd "$(dirname "$0")" && pwd)"      # запущен из корня репозитория
fi
if [ -n "$SRC_DIR" ]; then
    say "Использую локальные исходники: $SRC_DIR"
    [ -f "$SRC_DIR/install/install.sh" ] || die "в $SRC_DIR нет install/install.sh"
    WORKDIR="$SRC_DIR"
else
    say "Скачиваю Редут ($REPO, ветка $BRANCH)"
    rm -rf "$WORKDIR"; mkdir -p "$WORKDIR"
    url="https://codeload.github.com/${REPO}/tar.gz/refs/heads/${BRANCH}"
    if ! curl -fsSL "$url" | tar -xz -C "$WORKDIR" --strip-components=1; then
        die "не скачался $url — проверь имя репозитория (REPO=владелец/имя) и ветку"
    fi
    [ -f "$WORKDIR/install/install.sh" ] || die "в архиве нет install/install.sh — не тот репозиторий?"
fi
ok "исходники в $WORKDIR"

# ── 3. Параметры узла ───────────────────────────────────────────────────────
say "Определяю сетевые параметры"
cd "$WORKDIR"
python3 - "$NAME" "$SUBNET" "$CLIENTS" <<'PY' > "$WORKDIR/install/params.sh"
import os, re, subprocess, sys
sys.path.insert(0, "install")
import profiles

name, subnet, clients_spec = sys.argv[1], sys.argv[2], sys.argv[3]

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()

route = sh("ip route show default")
m = re.search(r"default via (\S+) dev (\S+)", route)
if not m:
    sys.exit("не определить шлюз/интерфейс")
gw, wan = m.group(1), m.group(2)
server_ip = sh("ip -4 -o addr show dev %s scope global | awk '{print $4}' | cut -d/ -f1 | head -1" % wan)

base = subnet.split("/")[0].rsplit(".", 1)[0]
if re.fullmatch(r"\d+", clients_spec):
    names = ["client%d" % i for i in range(1, int(clients_spec) + 1)]
else:
    names = [x.strip() for x in clients_spec.split(",") if x.strip()]
# Элемент можно задать как "имя" (адрес назначится сам) или "имя:10.8.0.5" —
# точный адрес нужен при переустановке поверх живого узла, чтобы у клиента не
# поменялся IP и его старый профиль продолжил работать.
clients = []
for i, n in enumerate(names):
    if ":" in n:
        nm, addr = n.split(":", 1)
        clients.append({"name": nm.strip(), "addr": addr.strip()})
    else:
        clients.append({"name": n, "addr": "%s.%d" % (base, 2 + i)})

# Имя базового профиля не хардкодим: в разных сборках оно своё, а нам нужны лишь
# его дефолты (порт wg, версия sing-box, параметры локального SOCKS). Если профиль
# с именем узла существует — берём его (как bootstrap.py: --profile по умолчанию
# равен --name); это важно при UPDATE=1, чтобы узел не получил чужие дефолты.
profile_name = os.environ.get("PROFILE") or (name if name in profiles.PROFILES
                                             else sorted(profiles.PROFILES)[0])
ov = {"subnet": subnet,
      # wg_ip профиля осмыслен только в его родной подсети: в чужой берём .1
      # действующей, иначе wg0/dnsmasq получили бы адрес не из подсети узла
      # (ловилось при UPDATE=1 узла, чьё имя не совпадает с профилем; ревью Ф2)
      "wg_ip": profiles.effective_wg_ip(profiles.PROFILES.get(profile_name, {}), subnet)}
# Режим обновления (UPDATE=1): dnsmasq и порт wg — с живого узла, не из профиля,
# иначе обновление молча переключило бы DNS-схему клиентов или порт WireGuard.
if os.environ.get("UPD_DNSMASQ") in ("0", "1"):
    ov["dnsmasq"] = os.environ["UPD_DNSMASQ"] == "1"
if (os.environ.get("UPD_WG_PORT") or "").isdigit():
    ov["wg_port"] = int(os.environ["UPD_WG_PORT"])
p = profiles.build_profile(profile_name, server_ip, "", ov)
p["name"], p["role"], p["clients"] = name, "vpn-%s" % name, clients
if os.environ.get("UPDATE") == "1":
    # Чужие секреты профиля обновлению не нужны: живой канал сохранит install.sh §5
    # (пустой upstream не «подарит» узлу чужой), а пустой пароль SOCKS5 заставит §8
    # СОХРАНИТЬ уже сгенерированный /etc/microsocks.env, вместо перезаписи паролем профиля.
    p["upstream"] = {"host": "", "socks": 0, "http": 0, "user": "", "pass": ""}
    p["microsocks"] = dict(p.get("microsocks") or {"port": 1080, "user": "proxyuser"}, **{"pass": ""})
sys.stdout.write(profiles.render_params(p, {"gw": gw, "wan": wan, "server_ip": server_ip}))
PY
chmod 600 "$WORKDIR/install/params.sh"
grep -E '^(SERVER_IP|WAN|GW|SUBNET|CLIENTS)=' "$WORKDIR/install/params.sh" | sed 's/^/  /'
ok "параметры готовы"

# ── 4. База: WireGuard, sing-box, маршруты, самолечение ─────────────────────
say "Ставлю базу узла (это самый долгий шаг, пара минут)"
bash "$WORKDIR/install/install.sh" 2>&1 | sed 's/^/  /'

# сторож самолечения (в публичной раскладке лежит в node/)
if [ -f "$WORKDIR/node/singbox-watchdog.sh" ]; then
    install -m 0755 "$WORKDIR/node/singbox-watchdog.sh" /usr/local/bin/singbox-watchdog.sh
    ok "сторож самолечения установлен"
fi

# ── 5. Агент и веб-панель ───────────────────────────────────────────────────
say "Ставлю агента и веб-панель"
# Панели нужно знать про dnsmasq: иначе новым клиентам, выданным через панель, проставляется
# DNS 1.1.1.1 вместо адреса dnsmasq — и белый список РФ у них не наполняется (найдено на node2
# 2026-08-17). Флаг берём из уже сгенерированного params.sh (профиль решает, вкл dnsmasq или нет).
DNSMASQ_FLAG=""
grep -q "^DNSMASQ='1'$" "$WORKDIR/install/params.sh" 2>/dev/null && DNSMASQ_FLAG="--dnsmasq"
# Порт wg — из params.sh (профиль или UPDATE-режим): иначе config.json панели получил бы
# дефолт 51820 даже там, где узел слушает другой порт.
WG_PORT_ARG=""
wgp="$(sed -n "s/^WG_PORT='\{0,1\}\([0-9]*\)'\{0,1\}$/\1/p" "$WORKDIR/install/params.sh" 2>/dev/null | head -1 || true)"
[ -n "$wgp" ] && WG_PORT_ARG="--wg-port $wgp"
out="$(python3 "$WORKDIR/install/setup_panel.py" --src "$WORKDIR/agent" \
        --name "$NAME" --port "$PANEL_PORT" --subnet "$SUBNET" $DNSMASQ_FLAG $WG_PORT_ARG)"
echo "$out" | grep -v '^{' | sed 's/^/  /' || true
json="$(echo "$out" | tail -1)"
SERVER_IP="$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('server_ip',''))" "$json")"
CERT_FP="$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('cert_fp',''))" "$json")"
FRESH="$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('fresh_setup'))" "$json")"

# ── 5b. Исходящий канал ещё не выбран (первая установка публичной сборки) ────
# Пока владелец не ввёл ключ провайдера в мастере, у sing-box нет upstream и туннель
# упирается в пустоту. Сторож заметил бы это через ≤2 мин и перевёл узел на прямой
# выход через адрес сервера (агент, режим EMERGENCY). Делаем это сразу, чтобы устройство,
# подключённое через минуту после установки, не сидело без сети до первого тика крона.
UP_NOW="$(python3 -c 'import json,sys
c = json.load(open(sys.argv[1], encoding="utf-8"))
print(next((o.get("server") or "" for o in c.get("outbounds", []) if o.get("tag") == "socks-out"), ""))' \
    /etc/sing-box/config.json 2>/dev/null || true)"
if [ -z "$UP_NOW" ]; then
    say "Исходящий канал ещё не выбран — включаю прямой выход до настройки провайдера"
    # boot-скрипт при пустом канале уже поставил прямой маршрут (install.sh §7, снос №4);
    # сторож/агент здесь заводят автомат в EMERGENCY, чтобы панель и журнал это объясняли.
    /usr/local/bin/singbox-watchdog.sh >/dev/null 2>&1 || true
    if ip route show table middleman 2>/dev/null | grep -q '^default via'; then
        ok "устройства выходят напрямую через $SERVER_IP (в панели это «аварийный режим» — норма для нового узла)"
    else
        printf '  \033[1;33m!\033[0m прямой выход не включился сам — сторож включит его в течение 2 минут\n'
    fi
fi

# ── 6. Проверка ─────────────────────────────────────────────────────────────
say "Проверяю, что всё поднялось"
fail=0
for s in wg-quick@wg0 sing-box vpn-boot-setup vpn-panel; do
    st="$(systemctl is-active "$s" 2>/dev/null || true)"
    if [ "$st" = "active" ]; then ok "$s"; else printf '  \033[1;31m✖\033[0m %s: %s\n' "$s" "$st"; fail=1; fi
done
hz="$(curl -sk --max-time 10 "https://127.0.0.1:${PANEL_PORT}/healthz" || true)"
if [ "$hz" = "ok" ]; then
    ok "панель отвечает по HTTPS"
else
    # Различаем «мертва» и «поднялась без TLS» (снос №6): пароль/2FA по HTTP недопустимы
    hp="$(curl -s --max-time 8 "http://127.0.0.1:${PANEL_PORT}/healthz" 2>/dev/null || true)"
    if [ "$hp" = "ok" ]; then
        printf '  \033[1;31m✖\033[0m панель работает по HTTP без TLS — пароль/2FA шли бы открытым текстом (сертификат не выпущен до старта)\n'
    else
        printf '  \033[1;31m✖\033[0m панель не отвечает\n'
    fi
    fail=1
fi

# SOCKS5 :1080 слушает весь интернет. Проверяем рукопожатием (RFC 1929), что пароль-заглушка
# из репозитория ОТВЕРГАЕТСЯ, а свой (из /etc/microsocks.env) ПРИНИМАЕТСЯ. Найдено на приёмке
# снос №4 (15.08): узел, поставленный одной командой, был открытым прокси с паролем с GitHub.
socks5_auth(){ # port user pass -> печатает accepted|rejected|noauth|down|error
python3 - "$@" <<'PY'
import socket, sys
port, user, pw = int(sys.argv[1]), sys.argv[2].encode(), sys.argv[3].encode()
try:
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(b"\x05\x01\x02")                       # SOCKS5, метод 2 = логин/пароль
    r = s.recv(2)
    if r == b"\x05\x00":
        print("noauth"); sys.exit(0)                 # пускает вообще без пароля
    if r != b"\x05\x02":
        print("error"); sys.exit(0)
    s.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(pw)]) + pw)
    r = s.recv(2)
    print("accepted" if r == b"\x01\x00" else "rejected")
except OSError:
    print("down")
PY
}
MS_PORT="$(sed -n "s/^MICROSOCKS_PORT='\{0,1\}\([0-9]*\)'\{0,1\}$/\1/p" "$WORKDIR/install/params.sh" 2>/dev/null | head -1 || true)"
MS_PORT="${MS_PORT:-1080}"
MS_USER=""; MS_PASS=""
if [ -r /etc/microsocks.env ]; then
    MS_USER="$(sed -n 's/^MICROSOCKS_USER=//p' /etc/microsocks.env | head -1 | sed 's/^"//; s/"$//' || true)"
    MS_PASS="$(sed -n 's/^MICROSOCKS_PASS=//p' /etc/microsocks.env | head -1 | sed 's/^"//; s/"$//' || true)"
fi
placeholder_res="$(socks5_auth "$MS_PORT" "${MS_USER:-proxyuser}" "CHANGE_ME_SOCKS_PASS" || true)"
own_res="no-env"
[ -n "$MS_PASS" ] && own_res="$(socks5_auth "$MS_PORT" "$MS_USER" "$MS_PASS" || true)"
if [ "$placeholder_res" = "rejected" ] && [ "$own_res" = "accepted" ]; then
    ok "SOCKS5 :$MS_PORT — свой пароль принят, заглушка из репозитория отвергнута"
elif [ "$placeholder_res" = "down" ]; then
    printf '  \033[1;31m✖\033[0m SOCKS5 :%s не отвечает (microsocks: %s)\n' "$MS_PORT" "$(systemctl is-active microsocks 2>/dev/null)"; fail=1
else
    printf '  \033[1;31m✖\033[0m SOCKS5 :%s — заглушка: %s, свой пароль: %s (ожидалось rejected/accepted)\n' "$MS_PORT" "$placeholder_res" "$own_res"; fail=1
fi

# ── 7. Итог ─────────────────────────────────────────────────────────────────
printf '\n\033[1;36m══════════════════════════════════════════════════════════\033[0m\n'
if [ "$fail" = "0" ]; then
    printf '\033[1;32m  Узел «Редут» готов\033[0m\n'
else
    printf '\033[1;33m  Узел поднят с замечаниями — смотри отметки выше\033[0m\n'
fi
printf '\033[1;36m══════════════════════════════════════════════════════════\033[0m\n\n'
if [ "$UPDATE" = "1" ]; then
    NEW_VER="$(cat "$WORKDIR/VERSION" 2>/dev/null || true)"
    printf '  Обновление узла «%s»: Редут %s → %s\n\n' "$NAME" "${OLD_VER:-?}" "${NEW_VER:-?}"
fi
if [ "$FRESH" = "True" ]; then
    printf '  Открой в браузере и пройди мастер первого входа:\n\n'
    printf '      \033[1;97mhttps://%s:%s/setup\033[0m\n\n' "$SERVER_IP" "$PANEL_PORT"
    printf '  \033[1;33mВАЖНО:\033[0m первый вход не защищён паролем — панель займёт тот,\n'
    printf '  кто откроет её первым. Пройди мастер сразу.\n\n'
else
    printf '  Панель уже настроена: https://%s:%s/\n\n' "$SERVER_IP" "$PANEL_PORT"
fi
printf '  Сертификат самоподписанный, браузер предупредит. Сверь отпечаток:\n'
printf '      %s\n\n' "$CERT_FP"
if [ -z "$UP_NOW" ]; then
    printf '  Исходящий канал появится после ввода ключа провайдера в мастере (шаг 3):\n'
    printf '  автоматика сама подберёт и применит канал из пула. До этого устройства выходят\n'
    printf '  в интернет напрямую через адрес сервера — панель показывает это как\n'
    printf '  «аварийный режим», для только что поставленного узла это ожидаемо.\n\n'
fi
printf '  Профили устройств выдаются в панели: раздел «Кто подключён» →\n'
printf '  имя устройства → «Выдать доступ» → QR для телефона или файл для компьютера.\n\n'
printf '  Клиентские конфиги на сервере: /etc/wireguard/clients/\n'
printf '  SOCKS5-прокси для приложений (по желанию): %s:%s, логин «%s»,\n' "$SERVER_IP" "$MS_PORT" "${MS_USER:-proxyuser}"
printf '  пароль сгенерирован при установке — смотри /etc/microsocks.env (только root).\n'
printf '  Повторный запуск этой команды безопасен — узел обновится, ключи сохранятся.\n\n'
